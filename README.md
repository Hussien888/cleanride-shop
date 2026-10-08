# CLEANRIDE – Launch-Ready Shop

CLEANRIDE ist jetzt als fokussierter Single-Product-Shop aufgebaut. Der Shop ist bewusst mit einem **Launch-Schutz** versehen: `SHOP_READY=false` verhindert echte Bestellungen, bis Lieferant, Produktdaten, Rechtstexte, Stripe und Testbestellung geprüft sind.

## Schnellster Livegang

1. Dieses Projekt in ein privates GitHub-Repository laden.
2. In Render **New → Blueprint** wählen und das Repository verbinden.
3. Die markierten Secret-/Betreiberfelder in `render.yaml` setzen.
4. Lieferantenkonditionen einholen und den tatsächlichen Lieferumfang festlegen. Siehe `SUPPLIER-PLAN.md`.
5. Stripe Live Key + Webhook eintragen.
6. SMTP eintragen und Testmails prüfen.
7. Rechtstexte mit deinen echten Betreiberangaben vervollständigen und rechtlich prüfen.
8. Eine echte Testbestellung durchführen.
9. Erst danach `SHOP_READY=true` setzen.

## Aktuelles Verkaufsmodell

- Produkt: CLEANRIDE Interior Detail Kit
- geplanter Startpreis: 34,90 €
- Standardversand: 4,90 €
- ab 60,00 € Warenwert versandkostenfrei
- maximal 10 Stück pro Checkout

Der Preis ist eine **Startannahme**, keine bestätigte Lieferantenkalkulation. Die echte Marge muss nach B2B-Freigabe neu berechnet werden.

## Lieferanten

Die aktuelle Prioritätenliste und die fertige B2B-Anfrage stehen in `SUPPLIER-PLAN.md`. Favorisiert werden zunächst Anbieter mit Deutschland-/EU-Versand und expliziter Wiederverkäufer-/Dropshipping-Möglichkeit.

## Marketing

`marketing/videos/pro/` enthält drei neue vertikale 1080×1920-Ads. `marketing/scripts/ads.md` enthält die Skripte. Keine erfundenen Kundenbewertungen oder nicht bestätigten Produktversprechen verwenden.

## Lokal testen

```bash
npm install
npm test
npm start
```

Ohne `SHOP_READY=true` nimmt der Checkout keine echten Bestellungen an. Ohne Stripe werden ebenfalls keine echten Online-Zahlungen gestartet.
