'use strict';
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');
const Stripe = require('stripe');
const L = require('./lib/logic');
const { makeStore } = require('./lib/store');
const pages = require('./lib/pages');

const env = process.env;
const PROD = env.NODE_ENV === 'production';
const PORT = Number(env.PORT || 3000);
const APP_URL = (env.APP_URL || env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`).replace(/\/$/, ''); // Render liefert RENDER_EXTERNAL_URL automatisch
const COMMISSION = Math.min(50, Math.max(0, Number(env.COMMISSION_PERCENT ?? 12)));
const COUPON = { code: (env.COUPON_CODE || '').trim().toUpperCase(), percent: Math.min(90, Math.max(0, Number(env.COUPON_PERCENT || 10))) };
const SHOP_PRODUCT = { id: 'cleanride-interior-kit', title: 'CLEANRIDE Interior Detail Kit', priceCents: Number(env.SHOP_PRICE_CENTS || 3490) };
const SHOP_SHIPPING_CENTS = Number(env.SHOP_SHIPPING_CENTS || 490);
const SHOP_READY = String(env.SHOP_READY || 'false').toLowerCase() === 'true';

// ---------- Start-Prüfungen (im Produktivbetrieb lieber nicht starten als unsicher starten) ----------
const weak = (s) => !s || s.length < 32 || /change|secret|dev-only/i.test(s);
if (PROD) {
  const problems = [];
  if (weak(env.JWT_SECRET)) problems.push('JWT_SECRET fehlt oder ist zu schwach (mind. 32 zufällige Zeichen).');
  if (!env.ADMIN_EMAIL || !env.ADMIN_PASSWORD || env.ADMIN_PASSWORD.length < 12 || /change|admin123/i.test(env.ADMIN_PASSWORD)) problems.push('ADMIN_EMAIL/ADMIN_PASSWORD fehlen oder sind unsicher (Passwort mind. 12 Zeichen).');
  if (!/^https:\/\//.test(APP_URL)) problems.push('APP_URL muss mit https:// beginnen.');
  if (problems.length) { console.error('Start abgebrochen:\n- ' + problems.join('\n- ')); process.exit(1); }
}
const JWT_SECRET = env.JWT_SECRET || crypto.randomBytes(32).toString('hex'); // lokal: Sitzungen enden beim Neustart

// ---------- Datenbank ----------
const DATA_DIR = env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'cleanride.db'));
db.pragma('journal_mode = WAL');
const store = makeStore(db);

const hash = (p) => bcrypt.hashSync(p, 12);
if (!store.adminExists()) {
  const email = (env.ADMIN_EMAIL || 'admin@werkbank.local').toLowerCase();
  store.createUser({ email, passwordHash: hash(env.ADMIN_PASSWORD || 'admin-lokal-123'), name: 'CLEANRIDE Admin', role: 'admin' });
  console.log(`Admin-Konto angelegt: ${email}`);
}
if (env.SEED_DEMO === 'true' && !db.prepare('SELECT 1 x FROM services LIMIT 1').get()) {
  const demo = store.createUser({ email: 'demo@cleanride.local', passwordHash: hash(crypto.randomBytes(24).toString('hex')), name: 'Demo-Anbieter' });
  [['Fahrradreparatur vor Ort', 'Handwerk', 'Hannover', 35, 'pro Stunde', 'Bremsen, Schaltung und Platten – direkt bei dir vor Ort.'],
   ['Logo & Markenauftritt', 'Design', 'Berlin', 480, 'pauschal', 'Logo, Farbwelt und Typografie für dein Projekt.'],
   ['Website in einer Woche', 'Digital', 'Remote', 900, 'pauschal', 'Saubere One-Pager mit Kontaktformular und Basis-SEO.'],
   ['Mathe-Nachhilfe Oberstufe', 'Unterricht', 'Hamburg', 32, 'pro Stunde', 'Analysis und Stochastik verständlich erklärt.'],
   ['Umzugshilfe mit Transporter', 'Haushalt', 'Köln', 55, 'pro Stunde', 'Zwei Helfer und Transporter für deinen Umzug.']]
    .forEach((r, i) => { const s = store.createService(demo.id, { title: r[0], category: r[1], city: r[2], price: r[3], unit: r[4], description: r[5] }, 'live'); if (i < 2) store.adminUpdateService(s.id, { featured: true }); });
  console.log('Demo-Angebote angelegt (SEED_DEMO=true). Vor dem Livegang SEED_DEMO=false setzen und Demo-Angebote im Admin löschen.');
}

// ---------- Mail & Zahlung ----------
const transport = env.SMTP_HOST ? nodemailer.createTransport({ host: env.SMTP_HOST, port: Number(env.SMTP_PORT || 587), secure: Number(env.SMTP_PORT) === 465, auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS } : undefined }) : null;
function mail(to, subject, body) {
  if (!transport || !to) return;
  transport.sendMail({ from: env.MAIL_FROM || 'noreply@example.com', to, subject: `CLEANRIDE: ${subject}`, text: `${body}\n\n— CLEANRIDE\n${APP_URL}` }).catch((e) => console.error('Mail-Fehler:', e.message));
}
const stripe = env.STRIPE_SECRET_KEY ? new Stripe(env.STRIPE_SECRET_KEY) : null;
const paymentsEnabled = !!stripe;

// ---------- App ----------
const app = express();
if (env.TRUST_PROXY) app.set('trust proxy', Number(env.TRUST_PROXY) || env.TRUST_PROXY);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: { useDefaults: false, directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'],
    connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"], frameAncestors: ["'none'"],
    ...(PROD ? { upgradeInsecureRequests: [] } : {}) } },
  hsts: PROD,
}));
app.use(compression());

// Stripe-Webhook braucht den unveränderten Body – deshalb vor express.json().
app.post('/api/payments/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripe || !env.STRIPE_WEBHOOK_SECRET) return res.status(503).end();
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], env.STRIPE_WEBHOOK_SECRET); }
  catch { return res.status(400).send('Ungültige Signatur'); }
  if (event.type === 'checkout.session.completed' && event.data.object.payment_status === 'paid') {
    const meta = event.data.object.metadata || {};
    const bookingId = Number(meta.bookingId);
    const orderId = Number(meta.orderId);
    if (bookingId && store.markPaid(bookingId)) {
      const b = store.getBooking(bookingId);
      if (b) {
        mail(b.customer_email, 'Zahlung erhalten', `Deine Zahlung über ${L.eur(b.total_cents)} für „${b.title}“ ist eingegangen.`);
        mail(b.provider_email, 'Buchung bezahlt', `„${b.title}“ am ${b.date} wurde bezahlt (${L.eur(b.total_cents)}). Auszahlung an dich: ${L.eur(b.payout_cents)}.`);
      }
    }
    if (orderId && store.markOrderPaid(orderId)) {
      const o = store.getOrder(orderId);
      if (o) mail(o.email, 'Bestellung bestätigt', `Danke für deine Bestellung #${o.id}. Dein CLEANRIDE Interior Cleaning Kit ist bestellt.`);
    }
  }
  res.json({ received: true });
});

app.use(express.json({ limit: '50kb' }));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, limit: 600, standardHeaders: true, legacyHeaders: false }));
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Zu viele Versuche. Bitte warte kurz.' } });

const tokenFor = (u) => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '7d' });
const publicUser = (u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, payoutReady: !!u.stripe_account_id });
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'Bitte melde dich an.' });
  try {
    const user = store.userById(jwt.verify(h.slice(7), JWT_SECRET).id); // Rolle immer frisch aus der DB
    if (!user) throw new Error('weg');
    req.user = user; next();
  } catch { res.status(401).json({ error: 'Sitzung abgelaufen. Bitte neu anmelden.' }); }
}
const adminOnly = (req, res, next) => (req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Nur für Administratoren.' }));
const id = (req) => Number(req.params.id);

// ---------- Öffentlich ----------
app.get('/api/health', (req, res) => res.json({ ok: true, payments: paymentsEnabled, mail: !!transport, shopReady: SHOP_READY }));
app.get('/api/config', (req, res) => res.json({ categories: L.CATEGORIES, units: L.UNITS, payments: paymentsEnabled, mail: !!transport, shopReady: SHOP_READY, commissionPercent: COMMISSION, coupon: COUPON.code ? { code: COUPON.code, percent: COUPON.percent } : null }));
app.get('/api/services', (req, res) => res.json({ services: store.listServices(req.query) }));
app.get('/api/services/:id', (req, res) => { const s = store.getPublicService(id(req)); s ? res.json({ service: s }) : res.status(404).json({ error: 'Angebot nicht gefunden.' }); });

// ---------- Shop ----------
app.post('/api/shop/checkout', async (req, res) => {
  if (!SHOP_READY) return res.status(503).json({error:'Der Shop ist noch im Launch-Modus. Bestellungen werden erst nach Lieferanten-, Zahlungs- und Rechtstext-Freigabe angenommen.'});
  const b = req.body || {};
  const productId = String(b.productId || '');
  const quantity = Math.min(10, Math.max(1, Math.floor(Number(b.quantity) || 0)));
  const name = String(b.name || '').trim().slice(0,100);
  const email = String(b.email || '').trim().toLowerCase().slice(0,254);
  const street = String(b.street || '').trim().slice(0,160);
  const zip = String(b.zip || '').trim();
  const city = String(b.city || '').trim().slice(0,80);
  const note = String(b.note || '').trim().slice(0,500);
  if (productId !== SHOP_PRODUCT.id) return res.status(400).json({error:'Produkt nicht gefunden.'});
  if (!quantity || !name || !/^\S+@\S+\.\S+$/.test(email) || !street || !/^\d{5}$/.test(zip) || !city) return res.status(400).json({error:'Bitte fülle alle Pflichtfelder korrekt aus.'});
  const subtotalCents = SHOP_PRODUCT.priceCents * quantity;
  const shippingCents = subtotalCents >= 6000 ? 0 : SHOP_SHIPPING_CENTS;
  const totalCents = subtotalCents + shippingCents;
  const o = store.createOrder({productId,productTitle:SHOP_PRODUCT.title,quantity,name,email,street,zip,city,note,subtotalCents,shippingCents,totalCents});
  mail(env.ADMIN_EMAIL, 'Neue CLEANRIDE-Bestellung', `Neue Bestellung #${o.id}: ${quantity} × ${SHOP_PRODUCT.title} für ${L.eur(totalCents)}. Kunde: ${name}, ${email}. Lieferadresse: ${street}, ${zip} ${city}.`);
  if (!stripe) {
    mail(email,'Bestellung eingegangen',`Wir haben deine Bestellung #${o.id} erhalten. Der Shop ist noch nicht für Online-Zahlungen freigeschaltet.`);
    return res.json({ok:true,message:`Bestellung #${o.id} wurde gespeichert. Online-Zahlung ist noch nicht aktiviert.`});
  }
  try {
    const session = await stripe.checkout.sessions.create({
      mode:'payment', customer_email:email,
      line_items:[{quantity,price_data:{currency:'eur',unit_amount:SHOP_PRODUCT.priceCents,product_data:{name:SHOP_PRODUCT.title}}}],
      shipping_options:[{shipping_rate_data:{type:'fixed_amount',fixed_amount:{amount:shippingCents,currency:'eur'},display_name:shippingCents?'Versand':'Kostenloser Versand',delivery_estimate:{minimum:{unit:'business_day',value:2},maximum:{unit:'business_day',value:5}}}}],
      metadata:{orderId:String(o.id)},
      success_url:`${APP_URL}/?order=success#/`, cancel_url:`${APP_URL}/?order=cancel#/`,
    });
    store.setOrderSession(o.id,session.id);
    res.json({url:session.url});
  } catch(e) { console.error('Shop Stripe:',e.message); res.status(502).json({error:'Zahlung konnte nicht gestartet werden. Bitte versuche es später erneut.'}); }
});
app.get('/api/shop/product',(req,res)=>res.json({product:SHOP_PRODUCT,shippingCents:SHOP_SHIPPING_CENTS,payments:paymentsEnabled}));

// ---------- Konto ----------
app.post('/api/auth/register', authLimiter, (req, res) => {
  const p = L.parseRegister(req.body);
  if (p.error) return res.status(400).json({ error: p.error });
  if (store.userByEmail(p.value.email)) return res.status(409).json({ error: 'Diese E-Mail ist bereits registriert.' });
  try {
    const user = store.createUser({ email: p.value.email, passwordHash: hash(p.value.password), name: p.value.name });
    res.status(201).json({ user: publicUser(user), token: tokenFor(user) });
  } catch (e) {
    if (String(e.code || '').includes('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'Diese E-Mail ist bereits registriert.' });
    throw e;
  }
});
app.post('/api/auth/login', authLimiter, (req, res) => {
  const u = store.userByEmail(String(req.body?.email || '').trim().toLowerCase());
  if (!u || !bcrypt.compareSync(String(req.body?.password || ''), u.password_hash)) return res.status(401).json({ error: 'E-Mail oder Passwort falsch.' });
  res.json({ user: publicUser(u), token: tokenFor(u) });
});
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
// Antwortet immer gleich, damit niemand herausfinden kann, welche E-Mail-Adressen registriert sind.
app.post('/api/auth/forgot', authLimiter, (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const u = email ? store.userByEmail(email) : null;
  if (u && transport) {
    const token = crypto.randomBytes(32).toString('hex');
    store.saveReset(u.id, sha256(token), new Date(Date.now() + 60 * 60 * 1000).toISOString());
    mail(u.email, 'Passwort zurücksetzen', `Hallo ${u.name},\n\nüber diesen Link kannst du ein neues Passwort festlegen (gültig für 1 Stunde):\n${APP_URL}/#/reset?token=${token}\n\nWenn du das nicht angefordert hast, kannst du diese E-Mail ignorieren.`);
  }
  res.json({ ok: true });
});
app.post('/api/auth/reset', authLimiter, (req, res) => {
  const password = String(req.body?.password ?? '');
  if (password.length < 10 || password.length > 72) return res.status(400).json({ error: 'Das Passwort muss 10 bis 72 Zeichen lang sein.' });
  const token = String(req.body?.token || '');
  const u = /^[0-9a-f]{64}$/.test(token) ? store.consumeReset(sha256(token), hash(password)) : null;
  if (!u) return res.status(400).json({ error: 'Dieser Link ist ungültig oder abgelaufen. Bitte fordere einen neuen an.' });
  res.json({ user: publicUser(u), token: tokenFor(u) });
});
app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));
app.delete('/api/me', auth, authLimiter, (req, res) => {
  if (req.user.role === 'admin') return res.status(400).json({ error: 'Das Admin-Konto kann nicht über die Oberfläche gelöscht werden.' });
  const u = store.userByEmail(req.user.email);
  if (!bcrypt.compareSync(String(req.body?.password || ''), u.password_hash)) return res.status(403).json({ error: 'Passwort falsch.' });
  res.json({ result: store.deleteAccount(req.user.id, hash(crypto.randomBytes(24).toString('hex'))) });
});

// ---------- Angebote (Anbieter) ----------
app.post('/api/services', auth, (req, res) => {
  const p = L.parseService(req.body);
  if (p.error) return res.status(400).json({ error: p.error });
  const s = store.createService(req.user.id, p.value);
  mail(env.ADMIN_EMAIL, 'Neues Angebot zur Prüfung', `${req.user.name} hat „${s.title}“ eingereicht.`);
  res.status(201).json({ id: s.id, status: s.status });
});
app.get('/api/my/services', auth, (req, res) => res.json({ services: store.myServices(req.user.id) }));
app.patch('/api/my/services/:id', auth, (req, res) => {
  const r = store.setOwnServiceStatus(id(req), req.user.id, req.body?.status);
  r.error ? res.status(400).json(r) : res.json(r);
});
app.delete('/api/my/services/:id', auth, (req, res) => { const r = store.deleteService(id(req), req.user.id); r.error ? res.status(400).json(r) : res.json(r); });

// ---------- Buchungen ----------
app.post('/api/bookings', auth, (req, res) => {
  const p = L.parseBooking(req.body);
  if (p.error) return res.status(400).json({ error: p.error });
  const s = store.getService(p.value.serviceId);
  if (!s || s.status !== 'live') return res.status(404).json({ error: 'Angebot nicht gefunden.' });
  if (s.user_id === req.user.id) return res.status(400).json({ error: 'Du kannst dein eigenes Angebot nicht buchen.' });
  const couponOk = COUPON.code && p.value.coupon === COUPON.code;
  if (p.value.coupon && !couponOk) return res.status(400).json({ error: 'Dieser Gutscheincode ist ungültig.' });
  const q = L.quote({ price: s.price, unit: s.unit, qty: p.value.qty, couponPercent: couponOk ? COUPON.percent : 0, commissionPercent: COMMISSION });
  const b = store.createBooking(req.user.id, s.id, p.value, q);
  mail(b.provider_email, 'Neue Anfrage', `${req.user.name} fragt „${b.title}“ für den ${b.date} an (${L.eur(b.total_cents)}).\n\nNachricht: ${b.message || '–'}\n\nBitte im Bereich „Mein Bereich“ bestätigen oder ablehnen.`);
  res.status(201).json({ bookingId: b.id, totalCents: b.total_cents, status: b.status });
});
const mine = (u) => (b) => ({ id: b.id, title: b.title, date: b.date, qty: b.qty, message: b.message, status: b.status, paymentStatus: b.payment_status, totalCents: b.total_cents, feeCents: b.fee_cents, payoutCents: b.payout_cents, createdAt: b.created_at, reviewRating: b.review_rating, serviceId: b.service_id, provider: b.provider, customer: b.customer, customerEmail: u === 'provider' || u === 'admin' ? b.customer_email : undefined });
app.get('/api/my/bookings', auth, (req, res) => res.json({ bookings: store.customerBookings(req.user.id).map(mine('customer')) }));
app.get('/api/my/requests', auth, (req, res) => res.json({ bookings: store.providerBookings(req.user.id).map(mine('provider')) }));
app.post('/api/bookings/:id/:action', auth, (req, res) => {
  const r = store.act(id(req), req.params.action, req.user, paymentsEnabled);
  if (r.error) return res.status(r.code || 400).json({ error: r.error });
  const b = r.booking, a = req.params.action;
  if (a === 'confirm') mail(b.customer_email, 'Anfrage bestätigt', `${b.provider} hat „${b.title}“ für den ${b.date} bestätigt. Du kannst jetzt im Bereich „Mein Bereich“ bezahlen.`);
  if (a === 'reject') mail(b.customer_email, 'Anfrage abgelehnt', `Leider hat ${b.provider} deine Anfrage zu „${b.title}“ abgelehnt.`);
  if (a === 'cancel') mail(b.provider_email, 'Anfrage storniert', `${b.customer} hat die Anfrage zu „${b.title}“ storniert.`);
  res.json({ ok: true, status: b.status });
});

// ---------- Bewertungen ----------
app.post('/api/reviews', auth, (req, res) => { const r = store.createReview(req.user.id, req.body || {}); r.error ? res.status(400).json(r) : res.status(201).json(r); });

// ---------- Zahlung (Stripe Connect: Geld geht an den Anbieter, die Plattform behält die Provision) ----------
app.post('/api/payments/checkout', auth, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Online-Zahlung ist noch nicht eingerichtet.' });
  const b = store.getBooking(Number(req.body?.bookingId));
  if (!b || b.customer_id !== req.user.id) return res.status(404).json({ error: 'Buchung nicht gefunden.' });
  if (b.status !== 'confirmed' || b.payment_status === 'paid') return res.status(400).json({ error: 'Diese Buchung kann gerade nicht bezahlt werden.' });
  if (!b.provider_account) return res.status(400).json({ error: 'Der Anbieter hat die Auszahlung noch nicht eingerichtet. Bitte später erneut versuchen.' });
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment', customer_email: req.user.email,
      line_items: [{ quantity: 1, price_data: { currency: 'eur', unit_amount: b.total_cents, product_data: { name: `${b.title} (${b.date})` } } }],
      payment_intent_data: { application_fee_amount: b.fee_cents, transfer_data: { destination: b.provider_account }, metadata: { bookingId: String(b.id) } },
      metadata: { bookingId: String(b.id) },
      success_url: `${APP_URL}/?payment=success#/konto`, cancel_url: `${APP_URL}/?payment=cancel#/konto`,
    });
    store.setSession(b.id, session.id);
    res.json({ url: session.url });
  } catch (e) { console.error('Stripe:', e.message); res.status(502).json({ error: 'Zahlung konnte nicht gestartet werden.' }); }
});
app.post('/api/connect/onboard', auth, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Online-Zahlung ist noch nicht eingerichtet.' });
  try {
    let acct = req.user.stripe_account_id;
    if (!acct) { acct = (await stripe.accounts.create({ type: 'express', country: 'DE', email: req.user.email })).id; store.setStripeAccount(req.user.id, acct); }
    const link = await stripe.accountLinks.create({ account: acct, type: 'account_onboarding', refresh_url: `${APP_URL}/#/konto`, return_url: `${APP_URL}/?connect=done#/konto` });
    res.json({ url: link.url });
  } catch (e) { console.error('Stripe Connect:', e.message); res.status(502).json({ error: 'Einrichtung der Auszahlung konnte nicht gestartet werden.' }); }
});
app.get('/api/connect/status', auth, async (req, res) => {
  if (!stripe || !req.user.stripe_account_id) return res.json({ connected: false, ready: false });
  try { const a = await stripe.accounts.retrieve(req.user.stripe_account_id); res.json({ connected: true, ready: !!a.charges_enabled && !!a.payouts_enabled }); }
  catch { res.json({ connected: true, ready: false }); }
});

// ---------- Admin ----------
const admin = [auth, adminOnly];
app.get('/api/admin/stats', ...admin, (req, res) => res.json({ ...store.stats(), commissionPercent: COMMISSION }));
app.get('/api/admin/services', ...admin, (req, res) => res.json({ services: store.adminServices() }));
app.patch('/api/admin/services/:id', ...admin, (req, res) => {
  const { status, verified, featured } = req.body || {};
  if (status !== undefined && !L.SERVICE_STATUS.includes(status)) return res.status(400).json({ error: 'Ungültiger Status.' });
  const r = store.adminUpdateService(id(req), { status, verified, featured });
  if (r.error) return res.status(400).json(r);
  if (status === 'live' || status === 'rejected') { const s = store.getService(id(req)); const o = store.userById(s.user_id); mail(o.email, status === 'live' ? 'Dein Angebot ist live' : 'Angebot abgelehnt', status === 'live' ? `„${s.title}“ ist jetzt veröffentlicht.` : `„${s.title}“ wurde leider nicht freigegeben.`); }
  res.json(r);
});
app.delete('/api/admin/services/:id', ...admin, (req, res) => { const r = store.deleteService(id(req), null); r.error ? res.status(400).json(r) : res.json(r); });
app.get('/api/admin/bookings', ...admin, (req, res) => res.json({ bookings: store.allBookings().map(mine('admin')) }));
app.get('/api/admin/users', ...admin, (req, res) => res.json({ users: store.adminUsers() }));

app.use('/api', (req, res) => res.status(404).json({ error: 'Nicht gefunden.' }));

// ---------- Seiten ----------
const PUB = path.join(__dirname, 'public'), VIEWS = path.join(__dirname, 'views'); // views = Vorlagen (werden gefüllt), public = fertige Dateien
const readPub = (f) => fs.readFileSync(path.join(VIEWS, f), 'utf8');
const INDEX = readPub('index.html'), NOT_FOUND = readPub('404.html');
const legalCtx = { commission: String(COMMISSION), payments: paymentsEnabled, mail: !!transport, today: L.todayBerlin().split('-').reverse().join('.') };
const legalHtml = {}; const legalMissing = new Set();
for (const name of pages.LEGAL_PAGES) { const r = pages.renderLegal(readPub(name + '.html'), env, legalCtx); legalHtml[name] = r.html; r.missing.forEach((m) => legalMissing.add(m)); }
if (legalMissing.size && PROD && env.ALLOW_MISSING_LEGAL !== 'true') {
  console.error(`Start abgebrochen: Für Impressum/Datenschutz fehlen Angaben (Abmahngefahr!). Bitte setzen: ${[...legalMissing].join(', ')}\n(Nur zum Testen umgehbar mit ALLOW_MISSING_LEGAL=true.)`);
  process.exit(1);
}
const html = (res, body, status = 200) => res.status(status).type('html').send(body);
const cache = PROD ? 'public, max-age=300' : 'no-cache';

app.get('/robots.txt', (req, res) => res.type('text/plain').send(pages.robotsTxt(APP_URL)));
app.get('/sitemap.xml', (req, res) => res.type('application/xml').send(pages.sitemapXml(APP_URL, store.listServices({}))));
app.get('/', (req, res) => { res.set('Cache-Control', 'no-cache'); html(res, pages.homePage(INDEX, APP_URL)); });
app.get('/angebot/:id', (req, res) => {
  const s = /^\d{1,9}$/.test(req.params.id) ? store.getPublicService(Number(req.params.id)) : null;
  if (!s) return html(res, NOT_FOUND, 404);
  res.set('Cache-Control', 'no-cache'); html(res, pages.offerPage(INDEX, APP_URL, s));
});
app.get('/:page(impressum|datenschutz|agb)', (req, res) => { res.set('Cache-Control', cache); html(res, legalHtml[req.params.page]); });
app.get(['/konto', '/admin', '/anbieten'], (req, res) => res.redirect(302, '/#' + req.path)); // Pfad-Links funktionieren auch ohne #
app.use(express.static(PUB, { index: false, maxAge: PROD ? '1h' : 0 }));
app.use((req, res) => (req.accepts('html') ? html(res, NOT_FOUND, 404) : res.status(404).end()));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Interner Fehler.' }); }); // eslint-disable-line

const server = app.listen(PORT, () => {
  console.log(`CLEANRIDE läuft auf ${APP_URL}  (Shop: ${SHOP_READY ? 'live' : 'Launch-Modus'}, Zahlung: ${paymentsEnabled ? 'an' : 'aus'}, Mail: ${transport ? 'an' : 'aus'})`);
  if (legalMissing.size) console.warn(`ACHTUNG: Für Impressum/Datenschutz fehlen noch Angaben: ${[...legalMissing].join(', ')}`);
  if (!transport) console.warn('Hinweis: SMTP ist nicht eingerichtet. Anbieter und Kunden bekommen keine E-Mails, und „Passwort vergessen“ funktioniert nicht.');
  if (!env.LEGAL_REVIEWED || env.LEGAL_REVIEWED !== 'true') console.warn('Hinweis: Rechtstexte sind Vorlagen. Nach der rechtlichen Prüfung LEGAL_REVIEWED=true setzen.');
});

function shutdown(signal) {
  console.log(`${signal}: fahre CLEANRIDE sauber herunter …`);
  server.close(() => {
    try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch {}
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000).unref();
}
process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));
