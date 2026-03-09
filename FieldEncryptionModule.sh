#!/bin/bash
# 1) Please modify the path to your REDCap-ROOT directory
# 2) Add a new cronjob
#    0 * * * * sh /var/www/redcap-test/modules/field_datacrypt_v1.0.0/FieldEncryption.sh
#    This CronJob runs ever hour at :00 and deletes the created decrypted data-csv-files
cd /var/www/redcap-test/temp/
rm ENC_*.csv
