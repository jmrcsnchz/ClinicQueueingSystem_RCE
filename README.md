# ClinicQueueingSystem RCE Proof-of-Concept
This exploits chains an Authorization Bypass (CVE-2024-0264) with Local File Inclusion (CVE-2024-0265) in [Sourcecodester Clinic Queuing System 1.0](https://www.sourcecodester.com/php/16439/clinic-queuing-system-using-php-and-sqlite3-source-code-free-download.html), leading to RCE

Usage:

```bash
python3 clinicx.py 'http://localhost/cqs'
```

![](https://raw.githubusercontent.com/jmrcsnchz/ClinicQueueingSystem_RCE/main/Screenshot%202024-01-03%20113757.png)


## Rootcause - Authorization Bypass (CVE-2024-0264)
The issue is systemic, affecting both `LoginRegistration.php` and `Master.php`. The validation of `formToken` had a logic flaw that led to it being bypassed.

```php
//LoginRegistration.php
// <SNIPPED>

extract($_POST);
$allowedToken = $_SESSION['formToken']['manage_user'];
if(!isset($formToken) || (isset($formToken) && $formToken != $allowedToken)){
    // throw new ErrorException("Security Check: Form Token is valid.");
    $resp['status'] = 'failed';
    $resp['msg'] = "Security Check: Form Token is invalid.";
}else{

// <SNIPPED>
```

In order for the request to be granted, the following conditions must be met:
- formToken must be set
- formToken should be equal to `$_SESSION['formToken']['manage_user']`

By sending the formToken as **BLANK** in the request, the validation can be bypassed as the null POST parameter will be **equal** to the null session variable.

## Rootcause - Local File Inclusion to RCE (CVE-2024-0265)
The GET parameter `page` was unsafely put inside an `include()` php function.

```php
//index.php
// <SNIPPED>

<?php include($page.".php");  ?>

// <SNIPPED>
```

The value of $page appended with `.php` was passed inside include. This can be exploited by leveraging PHP filters. In the exploit code, the technique [PHP Filter Chaining](https://github.com/synacktiv/php_filter_chain_generator) was used to gain RCE.
