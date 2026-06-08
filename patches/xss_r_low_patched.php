<?php

header("X-XSS-Protection: 1; mode=block");

if( array_key_exists("name", $_GET) && $_GET['name'] != NULL ) {

    $safe_name = htmlspecialchars(
        $_GET['name'],
        ENT_QUOTES,
        'UTF-8'
    );

    $html .= '<pre>Hello ' . $safe_name . '</pre>';
}

?>