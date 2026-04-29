# Cipher Watchdog

GitHub Actions prueft alle 30 Minuten `https://xynote.de/api/integrity` und sendet bei Fehlern eine Telegram-Nachricht.

## GitHub Secrets

In GitHub eintragen unter:

`Repository > Settings > Secrets and variables > Actions > New repository secret`

Benötigt:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

## Telegram

1. Bei Telegram `@BotFather` öffnen.
2. `/newbot` ausführen.
3. Bot-Token als `TELEGRAM_BOT_TOKEN` in GitHub speichern.
4. Dem Bot eine Nachricht senden.
5. Chat-ID ermitteln, z. B. mit:

```text
https://api.telegram.org/bot<DEIN_TOKEN>/getUpdates
```

Die Zahl bei `chat.id` als `TELEGRAM_CHAT_ID` speichern.

## Manuell testen

In GitHub:

`Actions > Cipher Watchdog > Run workflow`

Bei einem Fehler sendet der Workflow eine Telegram-Nachricht und markiert den Lauf als fehlgeschlagen.
