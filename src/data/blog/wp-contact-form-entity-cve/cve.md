---
author: Michail Solovev
pubDatetime: 2025-08-20T15:22:00Z
modDatetime: 2025-08-20T16:52:45.934Z
title: CVE-2025-7384
slug: wp-contact-form-entity-cve
featured: false
draft: false
tags:
  - cve
description:
  Strange CVE-2025-7384.
--- 

### Some Info

The CVE description caught my attention with the mention of `Contact Form 7`. I frequently noticed this plugin on WordPress sites, and since a vulnerability was reported, it seemed worth investigating.

Let’s review the description:

```
The Database for Contact Form 7, WPforms, Elementor forms plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 1.4.3 via deserialization of untrusted input in the get_lead_detail function. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain in the Contact Form 7 plugin, which is likely to be used alongside, allows attackers to delete arbitrary files, leading to a denial of service or remote code execution when the wp-config.php file is deleted.
```

This immediately struck me as odd—I had previously reviewed the `Contact Form 7` code and found no signs of serialization. The only notable vulnerability in it was related to file uploads.

During the investigation, it became clear that the vulnerability lies in a different plugin, not `Contact Form 7`.

The difference is as follows:

**Contact Form 7** - a plugin that integrates a contact form.

**Contact Form Entries** - one of the plugins that saves messages received via Contact Form 7 to a local database. There are many similar plugins.

### Plugin Detection:

```
http://example.com/wp-content/plugins/contact-form-entries/readme.txt
```

### Plugin Internals

When viewing form responses in `/wp-admin`, each field is checked by the plugin during UI rendering.


```php file=includes/data.php
public function get_lead_detail($lead_id){
    global $wpdb;
    $detail_table = $this->get_crm_table_name('detail');
    $sql=$wpdb->prepare("Select * from {$detail_table} where lead_id=%d",$lead_id);
    $detail_arr=$wpdb->get_results($sql,ARRAY_A);
 
    $detail=array();
    if(is_array($detail_arr)){
        foreach($detail_arr as $v){
            if(!empty($v['value'])){  
                $v['value']= $this->verify_val($v['value']);
            }
            $detail[$v['name']]=$v;     
        }  
    }
    return $detail;
}

public function verify_val($string){
    if(in_array(substr(ltrim($string),0,1),array('{','[')) && in_array(substr( rtrim($string), -1 ),array('}',']') )){
        $val=json_decode($string,1);  
        if(is_array($val)){
            $string=$val;   
        }
    }else if(is_serialized($string)){
        $string=maybe_unserialize($string);  
    } 
    return $string;  
}
```

Let’s break down `get_lead_detail`:

```php
public function get_lead_detail($lead_id){
    global $wpdb;
    // Retrieve form submission text from the WordPress database
    $detail_table = $this->get_crm_table_name('detail');
    $sql=$wpdb->prepare("Select * from {$detail_table} where lead_id=%d",$lead_id);
    $detail_arr=$wpdb->get_results($sql,ARRAY_A);
    // Iterate through the fields of each submission
    $detail=array();
    if(is_array($detail_arr)){
        foreach($detail_arr as $v){
            // If the field is not empty
            if(!empty($v['value'])){  
                // Verify the field value
                $v['value']= $this->verify_val($v['value']);
            }
            // Assign the value to the field for later display
            $detail[$v['name']]=$v;     
        }  
    }
    return $detail;
}
```

Let’s break down `verify_val`:

```php
public function verify_val($string){
    // Check for JSON format
    if(in_array(substr(ltrim($string),0,1),array('{','[')) && in_array(substr( rtrim($string), -1 ),array('}',']') )){
        $val=json_decode($string,1);  
        if(is_array($val)){
            $string=$val;   
        }
    // If not JSON, it might be a serialized value (why???)
    }else if(is_serialized($string)){
        $string=maybe_unserialize($string);  
    } 
    return $string;  
}
```

The WordPress core function `maybe_unserialize` indeed attempts to deserialize a string:


```php file=wp-includes/functions.php
function maybe_unserialize( $data ) {
    if ( is_serialized( $data ) ) { // Don't attempt to unserialize data that wasn't serialized going in.
        return @unserialize( trim( $data ) );
    }
    return $data;
}
```

Thus, the steps required are:

1. Submit data via Contact Form 7 with a serialized string as one of the values.
2. Wait for the admin to view the data saved by the plugin in the dashboard.

Automating the submission to the contact form can be done with the script below. However, to exploit the vulnerability, a gadget must be found in either the WordPress core or one of the plugins.

```python
import requests

def send_contact_form():
    target_url = input("Enter the target server URL (e.g., http://127.0.0.1): ").strip()
    message_text = input("Enter the message text (your-message): ").strip()

    endpoint = f"{target_url.rstrip('/')}/wp-json/contact-form-7/v1/contact-forms/10/feedback"

    data = {
        '_wpcf7': '10',
        '_wpcf7_version': '6.1.1',
        '_wpcf7_locale': 'en_US',
        '_wpcf7_unit_tag': 'wpcf7-f10-p6-o1',
        '_wpcf7_container_post': '6',
        '_wpcf7_posted_data_hash': '',
        'your-name': '123',
        'your-email': 'asd@ads.asd',
        'your-subject': '123',
        'your-message': message_text
    }

    files = {
        'your-message': (None, message_text),
        '_wpcf7': (None, '10'),
        '_wpcf7_version': (None, '6.1.1'),
        '_wpcf7_locale': (None, 'en_US'),
        '_wpcf7_unit_tag': (None, 'wpcf7-f10-p6-o1'),
        '_wpcf7_container_post': (None, '6'),
        '_wpcf7_posted_data_hash': (None, ''),
        'your-name': (None, '123'),
        'your-email': (None, 'asd@ads.asd'),
        'your-subject': (None, '123'),
    }

    # Simplified headers
    headers = {
        'Accept': 'application/json, */*;q=0.1',
        'Origin': target_url.rstrip('/'),
        'Referer': f"{target_url}/",
        'Connection': 'close'
    }

    try:
        response = requests.post(endpoint, files=files, headers=headers)
        print(f"\nStatus code: {response.status_code}")
        print("Server response:")
        print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error sending request: {e}")

if __name__ == "__main__":
    send_contact_form()
```

#### 1001 Exploitation Issues

1. When data is submitted through Contact Form 7, it is sanitized by the plugin, including via the `esc_html` function.

Thus, the serialized payload must not contain special characters. Moreover, when XSS-like payloads are submitted, they are completely removed rather than sanitized.

2. The core WordPress lacks potential deserialization gadgets.

I checked the WordPress source code for `__wakeup` and `__deserialize` methods. They exist in small numbers and are specifically designed to prevent deserialization.

Searching for methods like `__toString` in the WordPress core is pointless, as they are invoked during class operations and triggered by external events. Through deserialization, I can only create a class object, not use it elsewhere.

The plugin’s code also lacks dangerous objects.