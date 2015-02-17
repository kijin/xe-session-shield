<?php

/**
 * @file session_shield.addon.php
 * @author Kijin Sung <kijin@kijinsung.com>
 * @license LGPL v2.1 <http://www.gnu.org/licenses/lgpl-2.1.html>
 * @brief Session Shield addon
 * 
 * This addon improves session security by preventing XSS, session fixation,
 * and some types of sniffing attacks when SSL is only partially used.
 * 
 * This addon is experimental. It may cause problems in XE 1.6 ~ 1.7.7.2,
 * and when XE is used with SSO and/or virtual websites.
 */

if(!defined('__XE__')) exit;
if($called_position !== 'before_module_init') return;

require_once 'session_shield.class.php';
$shield = new Session_Shield();
$shield->initialize();
