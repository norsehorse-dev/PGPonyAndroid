# PGPony 4.6.4

Nitrokey 3 over USB, and four small fixes pulled forward from 4.7.0. 4.6.4 carries versionCode 464 and installs in place over 4.6.3.

## Nitrokey 3 over USB

Plugging a Nitrokey 3 into the phone failed with a status code that made no sense (0x0A3F). The key splits any
reply longer than one USB packet into several parts and waits for the phone to ask for each one. PGPony read only
the first part and took its last two bytes as the result. It now asks for every part and puts the reply back
together before reading it.

The Nitrokey 3 does not offer OpenPGP over NFC: Nitrokey turned it off in firmware 1.5.0. Use it over USB.

## Days left in Recently Deleted (#58)

Each key in Recently Deleted shows how many days it has left before it is destroyed, or "Less than a day left"
on its last day.

## One PGPony entry in the share menu (#58)

The separate "Encrypt in PGPony" share entry from 4.5.1 is gone. The Encrypt option in the PGPony Quick Action
does the same thing, so PGPony now appears once in the share menu.

## Key details

- User ID rows: Make Primary now comes after Revoke and Remove, so those two stay in the same place on every row
  (#76).
- The Revoke this subkey instead button in the subkey remove dialog now matches the key delete sheet: full width,
  with the same icon (#36).

## Verify this build

Hashes and signatures are added when the release is published.
