<?php

/**
 * @file session_shield.class.php
 * @author Kijin Sung <kijin@kijinsung.com>
 * @brief Session Shield class
 * 
 * This class contains all the session management features of the Session Shield addon.
 * It is implemented as a separate file for clarity and efficiency.
 */

class Session_Shield
{
	/**
	 * Class constants
	 */
	const ARRAY_KEY = 'XE_SESSION_SHIELD';
	const COOKIE_NAME = 'xe_shield';
	const COOKIE_NAME_SSL = 'xe_shield_ssl';
	const COOKIE_HASH_ALGO = 'sha1';
	const INIT_LEVEL_NONE = 0;
	const INIT_LEVEL_BASIC = 1;
	const INIT_LEVEL_SSL = 2;
	const REFRESH_TIMEOUT = 300;
	const GRACE_PERIOD = 30;
	
	/**
	 * Check if the session is active.
	 * 
	 * @return bool
	 */
	public function isSessionActive()
	{
		if(function_exists('session_status'))
		{
			return (session_status() === PHP_SESSION_ACTIVE);
		}
		else
		{
			return (session_id() !== '');
		}
	}
	
	/**
	 * Check if the session shield is usable in the current request.
	 * 
	 * @return bool
	 */
	public function isShieldEnabled()
	{
		$act = Context::get('act');
		$method = $_SERVER['REQUEST_METHOD'];
		if($act === 'procFileUpload' && $method !== 'GET')
		{
			return false;
		}
		return true;
	}
	
	/**
	 * Check if the current request uses SSL.
	 * 
	 * @return bool
	 */
	public function isSecureRequest()
	{
		return (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
	}
	
	/**
	 * Check if the user's browser is known to forget session cookies.
	 * 
	 * @return bool
	 */
	public function isStupidBrowser()
	{
		$ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
		if(strpos($ua, 'MSIE 8.0') !== false || strpos($ua, 'Trident/4.0') !== false) return true;
		if(strpos($ua, 'BlackBerry') !== false) return true;
		return false;
	}
	
	/**
	 * Get the member_srl of the current user.
	 * 
	 * @return int
	 */
	public function getMemberSrl()
	{
		if(!isset($_SESSION['is_logged']) || !$_SESSION['is_logged']) return 0;
		return isset($_SESSION['member_srl']) ? intval($_SESSION['member_srl']) : 0;
	}
	
	/**
	 * Initialize session variables for Session Shield.
	 * 
	 * @return bool
	 */
	public function initialize()
	{
		if(!$this->isSessionActive()) return false;
		if(!$this->isShieldEnabled()) return true;
		
		if(!isset($_SESSION[self::ARRAY_KEY]['login']))
		{
			$_SESSION[self::ARRAY_KEY] = array(
				'init' => self::INIT_LEVEL_NONE,
				'login' => $this->getMemberSrl(),
				'cookie' => array(
					'value' => $this->getRandomString(),
					'previous' => null,
					'last_refresh' => time(),
					'need_refresh' => false,
				),
				'cookie_ssl' => array(
					'value' => null,
					'previous' => null,
					'last_refresh' => null,
					'need_refresh' => false,
				),
			);
			if($this->isSecureRequest())
			{
				$_SESSION[self::ARRAY_KEY]['cookie_ssl'] = array(
					'value' => $this->getRandomString(),
					'previous' => null,
					'last_refresh' => time(),
					'need_refresh' => false,
				);
			}
			$this->setShieldCookies();
			return true;
		}
		
		if(!$this->checkCookies()) return false;
		if(!$this->checkTimeout()) return false;
		return true;
	}
	
	/**
	 * Check the cookies.
	 * 
	 * @return bool
	 */
	public function checkCookies()
	{
		if($_SESSION[self::ARRAY_KEY]['init'] == self::INIT_LEVEL_NONE) return false;
		
		$cookie = isset($_COOKIE[self::COOKIE_NAME]) ? $_COOKIE[self::COOKIE_NAME] : 'none';
		$cookie_ssl = isset($_COOKIE[self::COOKIE_NAME_SSL]) ? $_COOKIE[self::COOKIE_NAME_SSL] : 'none';
		
		if($cookie !== $_SESSION[self::ARRAY_KEY]['cookie']['value'] &&
			($cookie !== $_SESSION[self::ARRAY_KEY]['cookie']['previous'] ||
			$_SESSION[self::ARRAY_KEY]['cookie']['last_refresh'] < time() - self::GRACE_PERIOD))
		{
			$this->destroySession();
			return false;
		}
		
		if($this->isSecureRequest())
		{
			if($_SESSION[self::ARRAY_KEY]['init'] < self::INIT_LEVEL_SSL)
			{
				$this->refreshSession();
			}
			elseif($cookie_ssl !== $_SESSION[self::ARRAY_KEY]['cookie_ssl']['value'] &&
				($cookie_ssl !== $_SESSION[self::ARRAY_KEY]['cookie_ssl']['previous'] ||
				$_SESSION[self::ARRAY_KEY]['cookie_ssl']['last_refresh'] < time() - self::GRACE_PERIOD))
			{
				$this->destroySession();
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * Check the refresh timeout.
	 * 
	 * @return bool
	 */
	public function checkTimeout()
	{
		if(
			($this->getMemberSrl() !== $_SESSION[self::ARRAY_KEY]['login']) ||
			($_SESSION[self::ARRAY_KEY]['cookie']['need_refresh']) ||
			($_SESSION[self::ARRAY_KEY]['cookie_ssl']['need_refresh'] && $this->isSecureRequest()) ||
			($_SESSION[self::ARRAY_KEY]['cookie']['last_refresh'] < time() - self::REFRESH_TIMEOUT) ||
			($_SESSION[self::ARRAY_KEY]['cookie_ssl']['last_refresh'] < time() - self::REFRESH_TIMEOUT && $this->isSecureRequest()))
		{
			$this->refreshSession();
		}
		return true;
	}
	
	/**
	 * Set cookies related to Session Shield.
	 * 
	 * @return bool
	 */
	public function setShieldCookies()
	{
		if(headers_sent()) return false;
		
		$params = session_get_cookie_params();
		if($_SESSION[self::ARRAY_KEY]['cookie']['value'] !== null)
		{
			setcookie(self::COOKIE_NAME, $_SESSION[self::ARRAY_KEY]['cookie']['value'],
				$params['lifetime'], $params['path'], $params['domain'], false, true);
			$_SESSION[self::ARRAY_KEY]['init'] = max($_SESSION[self::ARRAY_KEY]['init'], self::INIT_LEVEL_BASIC);
		}
		if($_SESSION[self::ARRAY_KEY]['cookie_ssl']['value'] !== null && $this->isSecureRequest())
		{
			setcookie(self::COOKIE_NAME_SSL, $_SESSION[self::ARRAY_KEY]['cookie_ssl']['value'],
				$params['lifetime'], $params['path'], $params['domain'], true, true);
			$_SESSION[self::ARRAY_KEY]['init'] = max($_SESSION[self::ARRAY_KEY]['init'], self::INIT_LEVEL_SSL);
		}
		
		return true;
	}
	
	/**
	 * Refresh the session and all Session Shoeld cookies.
	 * 
	 * @return bool
	 */
	public function refreshSession()
	{
		if($this->isStupidBrowser() && $_SERVER['REQUEST_METHOD'] !== 'GET')
		{
			$_SESSION[self::ARRAY_KEY]['cookie']['need_refresh'] = true;
			if($this->isSecureRequest())
			{
				$_SESSION[self::ARRAY_KEY]['cookie_ssl']['need_refresh'] = true;
			}
			return false;
		}
		else
		{
			$precomputed_random1 = $this->getRandomString();
			$precomputed_random2 = $this->isSecureRequest() ? $this->getRandomString() : null;
			
			$previous_value = $_SESSION[self::ARRAY_KEY]['cookie']['value'];
			session_write_close(); $_SESSION = array(); session_start();
			if($_SESSION[self::ARRAY_KEY]['cookie']['value'] !== $previous_value)
			{
				return false;
			}
			
			$_SESSION[self::ARRAY_KEY]['cookie']['previous'] = $_SESSION[self::ARRAY_KEY]['cookie']['value'];
			$_SESSION[self::ARRAY_KEY]['cookie']['value'] = $precomputed_random1;
			$_SESSION[self::ARRAY_KEY]['cookie']['last_refresh'] = time();
			$_SESSION[self::ARRAY_KEY]['cookie']['need_refresh'] = false;
			if($this->isSecureRequest())
			{
				$_SESSION[self::ARRAY_KEY]['cookie_ssl']['previous'] = $_SESSION[self::ARRAY_KEY]['cookie_ssl']['value'];
				$_SESSION[self::ARRAY_KEY]['cookie_ssl']['value'] = $precomputed_random2;
				$_SESSION[self::ARRAY_KEY]['cookie_ssl']['last_refresh'] = time();
				$_SESSION[self::ARRAY_KEY]['cookie_ssl']['need_refresh'] = false;
			}
			$_SESSION[self::ARRAY_KEY]['login'] = $this->getMemberSrl();
			
			$previous_value = $_SESSION[self::ARRAY_KEY]['cookie']['value'];
			session_write_close(); $_SESSION = array(); session_start();
			if($_SESSION[self::ARRAY_KEY]['cookie']['value'] !== $previous_value)
			{
				return false;
			}
			
			return $this->setShieldCookies();
		}
	}
	
	/**
	 * Destroy the session and all Session Shield cookies.
	 * 
	 * @return bool
	 */
	public function destroySession()
	{
		if(headers_sent()) return false;
		
		$params = session_get_cookie_params();
		setcookie(self::COOKIE_NAME, '', time() - 86400, $params['path'], $params['domain'], false, false);
		setcookie(self::COOKIE_NAME_SSL, '', time() - 86400, $params['path'], $params['domain'], false, false);
		
		$oMemberController = getController('member');
		$oMemberController->destroySessionInfo();
		Context::set('is_logged', false);
		Context::set('logged_info', null);
		
		$_SESSION = array();
		return true;
	}
	
	/**
	 * Generate a 40-byte random string.
	 * 
	 * @return string
	 */
	public function getRandomString()
	{
		$is_windows = (defined('PHP_OS') && strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
		if(function_exists('openssl_random_pseudo_bytes') && (!$is_windows || version_compare(PHP_VERSION, '5.4', '>=')))
		{
			return hash(self::COOKIE_HASH_ALGO, openssl_random_pseudo_bytes(20));
		}
		elseif (function_exists('mcrypt_create_iv') && (!$is_windows || version_compare(PHP_VERSION, '5.3.7', '>=')))
		{
			return hash(self::COOKIE_HASH_ALGO, mcrypt_create_iv(20, MCRYPT_DEV_URANDOM));
		}
		else
		{
			$result = sprintf('%s %s %s', rand(), mt_rand(), microtime());
			for($i = 0; $i < 100; $i++)
			{
				$result = hash(self::COOKIE_HASH_ALGO, $result . mt_rand());
			}
			return $result;
		}
	}
}
