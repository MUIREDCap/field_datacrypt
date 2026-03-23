<?php
namespace EPICENTER\FieldEncryptionModule;

use ExternalModules\AbstractExternalModule;

require_once __DIR__ . '/UnsafeCrypto.php';
require_once __DIR__ . '/SaferCrypto.php';

/**
 * Field Encryption Module for REDCap
 *
 * Encrypts fields tagged with @DATACRYPT. Fields get stored as #ENC#_[base64]
 * created by 
 * @author Kshitiz Pokhrel <kpokhrel@torontomu.ca>
 * @author Ryan McRonald <rmcronald@uvic.ca>
 * REDCap Field Encryption Module
 * https://github.com/kpinsights/field_encryption_module_v1.0.0
 * modified by
 * @author Lalit Kaltenbach <redcap@i-med.ac.at>
 */
class FieldEncryptionModule extends AbstractExternalModule
{
    // Keeps track of records we're currently processing to avoid infinite loops
    private static $processingRecord = [];

    /**
     * Gets the encryption key from system settings
     */
    private function getEncryptionKey()
    {
        $keyHex = $this->getSystemSetting('encryption-key');
        if (empty($keyHex)) {
            throw new \Exception('Encryption key not configured');
        }
        return hex2bin($keyHex);
    }

    /**
     * Looks up which fields have the @DATACRYPT action tag
     */
    private function getFieldsToEncrypt($project_id = null)
    {
        $project_id = $project_id ?? $this->getProjectId();
        $dictionary = \REDCap::getDataDictionary($project_id, 'array');

        if (empty($dictionary)) {
            return [];
        }

        $fieldsToEncrypt = [];
        foreach ($dictionary as $fieldName => $fieldInfo) {
            $actionTags = $fieldInfo['field_annotation'] ?? '';
            $fieldType  = $fieldInfo['field_type'] ?? '';
            // Only fields of type text (Textbox) or notes (Freetext) 
            if (stripos($actionTags, '@DATACRYPT') !== false && ($fieldType ==='text' || $fieldType === 'notes')) {
                $fieldsToEncrypt[] = $fieldName;
            }
        }
        
        return $fieldsToEncrypt;
    }
    
    /**
     * Looks up which fields have the @DATACRYPT action tag
     * and check if user is allowed to export those fields
     */
    private function getFieldsToExport($project_id = null)
    {
        global $user_rights;
        
        $project_id = $project_id ?? $this->getProjectId();
        $dictionary = \REDCap::getDataDictionary($project_id, 'array');

        if (empty($dictionary)) {
            return [];
        }
                
        // Berechtigungen
        foreach($user_rights['forms'] as $key=>$formname) {
            $form_rights[$key] = $user_rights['forms_export'][$key];
        }
        
        

        $fieldsToExport = [];
        foreach ($dictionary as $fieldName => $fieldInfo) {
            $actionTags = $fieldInfo['field_annotation'] ?? '';
            $fieldType  = $fieldInfo['field_type'] ?? '';
            // Only fields of type text (Textbox) or notes (Freetext) 
            if (stripos($actionTags, '@DATACRYPT') !== false && ($fieldType ==='text' || $fieldType === 'notes')) {
                switch($form_rights[$fieldInfo['form_name']]) {
                    case 0:         // no access
                        break;
                    case 1:         // full access
                        $fieldsToExport[] = $fieldName;
                        break;
                    case 2:         // anonymous
                        if($fieldInfo['identifier']!== 'y' && $fieldType !== 'notes') {
                            $fieldsToExport[] = $fieldName;
                        }     
                        break;
                    case 3:         // without identifer                    
                        if($fieldInfo['identifier']!== 'y') {
                            $fieldsToExport[] = $fieldName;
                        }     
                        break;                       
                }
            }
        }
        
        return $fieldsToExport;
    }    

    /**
     * Encrypts a value and formats it as a fake email address
     * Output format: ENC_[url-safe-base64]
     */
    public function encryptValue($plaintext)
    {
        $key = $this->getEncryptionKey();
        $encrypted = SaferCrypto::encrypt($plaintext, $key, true);

        // Make it URL-safe: swap +/ for -_ and drop padding
        $urlSafe = rtrim(strtr($encrypted, '+/', '-_'), '=');
        return '#ENC#_' . $urlSafe ;
    }

    /**
     * Decrypts a value if it matches our encrypted format
     */
    public function decryptValue($encryptedValue)
    {
        // Not our format? Return as-is
        if (strpos($encryptedValue, '#ENC#_') !== 0) {
            return $encryptedValue;
        }

        // Strip the ENC_ prefix and convert back to standard base64
        $urlSafeBase64 = substr($encryptedValue, 6);
        $base64 = strtr($urlSafeBase64, '-_', '+/');

        // Restore padding
        $remainder = strlen($base64) % 4;
        if ($remainder) {
            $base64 .= str_repeat('=', 4 - $remainder);
        }

        $key = $this->getEncryptionKey();
        return SaferCrypto::decrypt($base64, $key, true);
    }

    /**
     * Hook: runs after a record is saved via data entry
     */
    public function redcap_save_record($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        $this->encryptRecordData($project_id, $record, $instrument, $event_id, $repeat_instance);
    }

    /**
     * Hook: runs after a survey is submitted
     */
    public function redcap_survey_complete($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        $this->encryptRecordData($project_id, $record, $instrument, $event_id, $repeat_instance);
    }

    /**
     * Main encryption logic, fetches record data and encrypts tagged fields
     */
    private function encryptRecordData($project_id, $record, $instrument, $event_id, $repeat_instance)
    {
        $repeat_instance = $repeat_instance ?: 1;
        $recordKey = "$project_id:$record:$event_id:$repeat_instance";

        // Bail out if we're already processing this record (prevents loops)
        if (isset(self::$processingRecord[$recordKey])) {
            return;
        }
        self::$processingRecord[$recordKey] = true;

        try {
            $this->log("Starting encryption", [
                'project_id' => $project_id,
                'record' => $record,
                'instrument' => $instrument,
                'event_id' => $event_id
            ]);

            $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);
            if (empty($fieldsToEncrypt)) {
                return;
            }

            // Pull the current record data
            $params = [
                'project_id' => $project_id,
                'return_format' => 'array',
                'records' => [$record],
                'events' => [$event_id]
            ];
            if ($repeat_instance > 1) {
                $params['redcap_repeat_instance'] = $repeat_instance;
            }

            $data = \REDCap::getData($params);
            if (empty($data) || !isset($data[$record][$event_id])) {
                $this->log("Could not fetch record data", [
                    'record' => $record,
                    'event_id' => $event_id,
                    'has_data' => !empty($data),
                    'has_record' => isset($data[$record]),
                    'has_event' => isset($data[$record][$event_id])
                ]);
                return;
            }

            $recordData = $data[$record][$event_id];

            // Handle repeating instruments
            if ($repeat_instance > 1 && isset($recordData['repeat_instances'][$instrument][$repeat_instance])) {
                $recordData = $recordData['repeat_instances'][$instrument][$repeat_instance];
            }

            // Go through each tagged field and encrypt if needed
            $updatedData = [];
            foreach ($fieldsToEncrypt as $fieldName) {
                if (!isset($recordData[$fieldName])) {
                    continue;
                }

                $value = $recordData[$fieldName];

                // Skip if empty or already encrypted
                $alreadyEncrypted = (strpos($value, '#ENC#_') === 0);
                if (empty($value) || $alreadyEncrypted) {
                    continue;
                }

                $updatedData[$fieldName] = $this->encryptValue($value);
            }

            // Save the encrypted values back
            if (!empty($updatedData)) {
                $saveData = [$record => [$event_id => $updatedData]];
                
                $result = \REDCap::saveData($project_id, 'array', $saveData, 'overwrite','YMD','flat',null,true,true,true,false,true,null,false,true,false,false,false,null,false,"",false,false,true,false,false);

                if (empty($result['errors'])) {
                    $this->log("Encrypted fields saved", [
                        'record' => $record,
                        'fields' => implode(', ', array_keys($updatedData))
                    ]);

                    \REDCap::logEvent(
                        "Field Encryption Module",
                        "Encrypted fields: " . implode(', ', array_keys($updatedData)),
                        null, $record, null, $project_id
                    );

                } else {
                    $this->log("Failed to save encrypted data", [
                        'record' => $record,
                        'errors' => json_encode($result['errors']),
                        'warnings' => json_encode($result['warnings']),
                        'ids' => json_encode($result['ids']),
                        'item_count' => json_encode($result['item_count'])
                    ]);
                }
            }

        } catch (\Exception $e) {
            $this->log("Encryption error", [
                'record' => $record,
                'error' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine()
            ]);
        } finally {
            unset(self::$processingRecord[$recordKey]);
        }
    }

    /**
     * Hook: shows a notice on data entry forms that have encrypted fields
     */
    public function redcap_data_entry_form_top($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
    {
        global $lang;
        $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);
        if (!empty($fieldsToEncrypt)) {
            $fields = "";
            if($lang['fieldencryption_1']!="") {
                echo $lang['fieldencryption_1'].implode(', ',$fieldsToEncrypt)."</i></li></ul></div><br />";
            } else  {
              echo "<div style='background-color:#fff3cd;border:1px solid #ffc107;padding:10px;margin:10px 0;border-radius:4px;width:50%'>
                <strong>Privacy Notice:</strong> The following fields are stored encrypted in the database:<ul><li><i>
                ".implode(',',$fieldsToEncrypt)."</i></li></ul></div><br />";
            }
        }
    }

    /**
     * Hook: masks encrypted values on data entry forms
     */
    public function redcap_data_entry_form($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
    {
        $this->outputFieldDecryptingScript($project_id, $record, $instrument, $event_id, $repeat_instance);
    }

    /**
     * Hook: masks encrypted values on survey pages (for returning participants)
     */
    public function redcap_survey_page($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        // Only mask if there's already a response (not a fresh survey)
        if (!empty($record) && !empty($response_id)) {
            $this->outputFieldDecryptingScript($project_id, $record, $instrument, $event_id, $repeat_instance);
        }
    }

    /**
     * Outputs JS that decrypted values in the UI
     * Wrapped in IIFE to avoid global scope pollution
     */
    private function outputFieldDecryptingScript($project_id, $record, $instrument, $event_id, $repeat_instance)
    {

        $repeat_instance = $repeat_instance ?: 1;
        $recordKey = "$project_id:$record:$event_id:$repeat_instance";

        // Bail out if we're already processing this record (prevents loops)
        if (isset(self::$processingRecord[$recordKey])) {
            return;
        }
        self::$processingRecord[$recordKey] = true;

        try {
            $this->log("Starting decryption", [
                'project_id' => $project_id,
                'record' => $record,
                'instrument' => $instrument,
                'event_id' => $event_id
            ]);
            
            $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);
            if (empty($fieldsToEncrypt)) {
              return;
            }        
            
            $params = [
                'project_id' => $project_id,
                'return_format' => 'array',
                'records' => [$record],
                'events' => [$event_id]
            ];
                     
            $data = \REDCap::getData($params);
            if (empty($data) || !isset($data[$record][$event_id])) {
                $this->log("Could not fetch record data", [
                    'record' => $record,
                    'event_id' => $event_id,
                    'has_data' => !empty($data),
                    'has_record' => isset($data[$record]),
                    'has_event' => isset($data[$record][$event_id])
                ]);
                return;
            }

            $recordData = $data[$record][$event_id];
            
            echo "<script type='text/javascript'>";
            
            foreach ($fieldsToEncrypt as $fieldName) {
                if (!isset($recordData[$fieldName])) {
                    continue;
                }
                
                $value = $recordData[$fieldName];
                 
                if (empty($value) || strpos($value, '#ENC#_')!==0) {
                    continue;
                }
               
                $updateValue = $this->decryptValue($value); 
                
                $output =  "var fieldName = '$fieldName';\n
                            var escapedFieldName = fieldName.replace(/([!\"#$%&'()*+,.\\/:;<=>?@\\[\\]^`{|}~])/g, '\\\\$1');\n
                            var field = $('input[name=\"' + escapedFieldName + '\"], textarea[name=\"' + escapedFieldName + '\"]');\n
                            if (field.length && field.val()) {\n
                                var currentValue = field.val().toString();\n
                                field.val('$updateValue');\n
                            }\n";
                echo htmlentities($output);
            }               
            echo "</script>";    
                                 
        } catch (\Exception $e) {
            $this->log("Encryption error", [
                'record' => $record,
                'error' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine()
            ]);
        }
    }

    /**
     * Creates a new Block for exporting the decrytped values
     */
    public function includeJsAndCss($new_url, $download="",$nodata=false)
    {
        global $lang;
        if($lang['fieldencryption_2']=="" && $lang['fieldencryption_3']=="" && $lang['fieldencryption_4']=="" && $lang['fieldencryption_5']=="" && $lang['fieldencryption_6']=="") {
            $lang['fieldencryption_2'] = "Export encrypted data with RecordID";
            $lang['fieldencryption_3'] = "Export all encrypted data decoded with the respective RecordID as a CSV file";
            $lang['fieldencryption_4'] = "Generate decoded data";
            $lang['fieldencryption_5'] = "Download decoded data";
            $lang['fieldencryption_6'] = "<br /><br /><b>Step 1:</b> Press the Key-Icon<br /><b>Step 2:</b> Press the Excel-Icon for download the csv-file<br /><br /><i><u>Notice:</u> The created file will be automatically deleted from the server at the top of each hour!</i>";
            $lang['fieldencryption_7'] = "No @DATACRYPT-Action-Tag in use<br />in this Project";
        }
        $alttext = ($download=="") ? $lang['fieldencryption_4'] : $lang['fieldencryption_5'];
        $usedimg = ($download=="") ? "FieldEncryptionModule.png" : "FieldEncryptionModule.gif"; 
        $link    = ($nodata==false) ? "<a href='".$new_url."' title='".$alttext."' ".$download."><img src='".$this->getUrl($usedimg)."'></a>" : $lang['fieldencryption_7'];
        echo "<script type='text/javascript'>";
        echo "$(function() {
                    'use strict';
                    $( document ).ready(function() {
                        $('#simple_export').append(\"<div class='spacer' style='border-color:#ccc; max-width: 780px;'></div>\");
                        $('#simple_export').append(\"<table cellspacing='0' width='100%'><tr><td valign='top' style='padding:5px 10px 5px 30px;border-right:1px solid #eee;'><div style='margin-bottom:7px;'><i class='fas fa-file-code fs14'></i><b>".$lang['fieldencryption_2']."</b></div>".$lang['fieldencryption_3'].$lang['fieldencryption_6']."</td><td valign='top' style='padding-top:5px;width:120px;text-align:center;''>".$link."</td></tr></table>\");
                    });   
             });";
        echo "</script>";
    }
    
    
    /**
     * Hook: Every Page
     */
	public function redcap_every_page_top($project_id) {
        if(PAGE==="DataExport/index.php") {
           if(isset($_GET['patient_data'])) {
             switch($_GET['patient_data']) {
                case 1: $this->createCSV($project_id); break;
             }
           } else { 
             $this->includeJsAndCss('https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] . "&amp;patient_data=1");
           }
        }
	}

    /**
     * Function: Creates the Identificationlist as csv with decrypted values and recordID
     */
    public function createCSV($project_id) {
        global $app_title;
        global $user_rights;
        $fieldsToEncrypt = $this->getFieldsToExport($project_id);
        if (!empty($fieldsToEncrypt)) {
            $group = ($user_rights['group_id']!==null) ? $user_rights['group_id'] : null; 
            $data = \REDCap::getData($project_id,'array',null,$fieldsToEncrypt,null,$group);
            // FileName
            $basename = camelCase(html_entity_decode($app_title, ENT_QUOTES)) . "_DBCryptedValue_" . date("Y-m-d_Hi") . ".csv";
            $filename = $_SERVER['DOCUMENT_ROOT']."/temp/ENC_".$basename;
            $download = 'https://' . $_SERVER['HTTP_HOST'] ."/temp/ENC_".$basename;
            // Create Header
            $header[] = "RecordID";
            foreach($fieldsToEncrypt as $fields) {
                $header[] = $fields;
            }
            // Begin writing
            $fp = fopen($filename,"w+");
            if($fp) {
                fputcsv($fp,$header,";","\"","\\","\n");
                foreach($data as $key1=>$value1) {
                    foreach($value1 as $key2=>$value2) {
                        unset($row);
                        $row[] = $key1;
                        foreach($value2 as $key3=>$value3) {
                            if (!empty($value3) && strpos($value3,'#ENC#_')===0) {
                                $row[] = $this->decryptValue($value3);
                            } else {
                                $row[] = "";
                            }
                        }
                        fputcsv($fp,$row,";","\"","\\","\n");
                    }
                }
                fclose($fp);
                $this->includeJsAndCss($download,"download");
            } else {
               print "Error: Could not write file into temp-folder.";
               exit();                                
            }
        } else {
            $this->includeJsAndCss("","",true);    
        }
    }
    
    /**
     * Hook: masks encrypted values in reports
     */
    public function redcap_report_data($project_id, $data, $fields, $events, $groups, $records)
    {
        $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);
        if (empty($fieldsToEncrypt)) {
            return $data;
        }

        foreach ($data as &$row) {
            foreach ($fieldsToEncrypt as $fieldName) {
                if (!empty($row[$fieldName]) && strpos($row[$fieldName], '#ENC#_') === 0)  {
                    $row[$fieldName] = $this->decryptValue($row[$fieldName]); 
                }
            }
        }
        return $data;
    }
}
