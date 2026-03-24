# REDCap Field Encryption Module

An External Module that encrypts field values marked with `@DATACRYPT`. Designed for studies that need to collect participant personal data and need those data to be stored crypted in database and unavailable to
gernerally export them.

## The Problem

REDCap stores every data in plaintext into databases

## What This Module Does

When a user or a participant enters personal data, the module encrypts it during the saving process into the database in a format like `#ENC#_...`. 
Those personal data are crypted if you export the data anyway. If you load a form or generate a report those data are shown decrypted. Also is in
the tab under `Other export options` at the end a new possibility to export all crypted data with the refering [record_id] as a csv-file for separate
documentation. 


## Requirements

- REDCap 16.1.4+ (if you want to use it with the german translation)
- PHP 7.4.0+
- External Module Framework v14
- Optional: German Translation File REDCap 16.1.8

## Installation

1. Place the module folder in your REDCap `modules` directory
2. Enable the module in Control Center > External Modules
3. Configure the Master Encryption Key (generate one with `openssl rand -hex 32`)
4. Enable for your project
5. CronJob for deleting the generated files
   0 * * * * sh /var/www/redcap-test/modules/field_datacrypt_v1.0.0/FieldEncryptionModule.sh
6. The "FieldEncryptionModule.sh" should be executable by the root user or the the user runs the cronjob
7. As well as the path should be modified to your system

## Usage

Add `@DATACRYPT` to field's action tags. That field will be encrypted on save. Only Textboxes and Noteboxes
are affected by this action tag! If you use it on other field types, nothing would happen

## De-/Encryption

The module uses SaferCrypto, which implements AES-256-CTR with HMAC-SHA256 authentication (encrypt-then-MAC).

Encrypted values are base64 encoded, converted to URL-safe characters, and formatted as `#ENC#_[data]`.

The encryption classes (UnsafeCrypto and SaferCrypto) are based on code by [Scott Arciszewski](https://stackoverflow.com/questions/9262109/simplest-two-way-encryption-using-php), licensed under CC BY-SA 4.0.

## What the Module does at each step

**On record save / survey submit:**
- Hooks `redcap_save_record` and `redcap_survey_complete` fire
- Module reads the data dictionary for fields with `@DATACRYPT`
- Fetches the saved record data via `REDCap::getData()`
- Encrypts any unencrypted values and saves them back via `REDCap::saveData()`

**On data entry form load:**
- Shows a privacy notice banner at the top of forms with encrypted fields names (NOT labels)
- JavaScript replaces any `#ENC#_` values with `original decrypted values`

**On survey page load (returning participants only):**
- JavaScript replaces any `#ENC#_` values with `original decrypted values`

**On report generation:**
- The `redcap_report_data` hook replaces any `#ENC#_` values with `original decrypted values`

**Dataexport => Other Exportoptions**
- At the end of the site an option vor exporting the crypted values with the record_id as a cvs
- Do this in 2 Steps
  Step 1: Press the Key-Icon 
  .. if there are data available (means you used @DATACRYPT-Action-Tag in your project)
  Step 2: Press the Excel-Icon vor downloading the csv-file
  .. if there are no data available (means you didn't use @DATACRYPT-Action-Tag in your project)
  A message tells you that no data are available for export
- The Script takes in account the users rights on exporting data  
- The created export-files (csv) are removed at the end of the hour within the files are generated on the server
  which would be done by the cronjob and the "FieldEncryptionModule.sh"
- The export-file will be saved in the {REDCAP-ROOT}/temp directory  

## Files

| File | Description |
|------|-------------|
| `FieldEncryptionModule.php` | Main module class |
| `FieldEncryptionModule.png` | Icon for the 'Generating CSV' |
| `FieldEncryptionModule.gif` | Excel Icon for Download CSV (modified from Redcap's excelicon.gif |
| `FieldEncryptionModule.sh`  | Script for CronJob for deleting the ENC_???.csv-Files from {REDCAP_ROOT}/temp directory |
| `SaferCrypto.php` | Authenticated encryption (encrypt-then-MAC) |
| `UnsafeCrypto.php` | AES-256-CTR encryption |
| `config.json` | Module settings, hooks, cron definition |
| `.htaccess` | Example access control for {REDCAP_ROOT}/temp/ directory |

## Security Notes

- Decrypted values are never written to logs
- SQL queries use parameterized statements via `$module->query()`
- JavaScript is wrapped in an IIFE to avoid global scope pollution
- Field names are JSON-encoded with `JSON_HEX_*` flags to prevent XSS

## Limitations

- If you lose the encryption key, encrypted data is unrecoverable (centralized by administration)

## Troubleshooting

**Field not encrypting:** Verify `@DATACRYPT` is in the field's action tags. Check EM logs for "Could not fetch record data" which indicates an event/instrument mismatch.

**Offering .html-file for download instead of csv. Check if webserver is allowed to write to the {REDCAP-ROOT}/temp directory and if you are allowed to read files over the
  Webbrowser from the folder {REDCAP-ROOT}/temp (.htaccess with "Require all denied" would block, solution: add
  --- .htaccess ---
  Require all denied
  <FilesMatch "^ENC_.*\.csv$">
     Require all granted
  </FilesMatch>
  -----------------
  Rights: root:www-data or apache, 640 => rw-r-----  

## Authors

Lalit Kaltenbach - Medical University of Innsbruck (redcap@i-med.ac.at)

## License

MIT License. See LICENSE file.
