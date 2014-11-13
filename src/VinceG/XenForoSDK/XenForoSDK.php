<?php

namespace VinceG\XenForoSDK;

/**
 * XenForo SDK
 * 
 * @author Vincent Gabriel <vadimg88@gmail.com>
 * @since 01/21/14
 * @version 0.0.1
 */
class XenForoSDK
{
	public function __construct($fileDir) {
		$startTime = microtime(true);

		require($fileDir . '/library/XenForo/Autoloader.php');
		\XenForo_Autoloader::getInstance()->setupAutoloader($fileDir . '/library');

		\XenForo_Application::initialize($fileDir . '/library', $fileDir);
		\XenForo_Application::set('page_start_time', $startTime);
		\XenForo_Session::startPublicSession();
	}

	public function getVisitor() {
		return \XenForo_Visitor::getInstance();
	}

	public function getSession() {
		return \XenForo_Application::get('session');
	}

	public function getOptions() {
		return \XenForo_Application::get('options');
	}

	public function getOption($key, $val=null) {
		return $this->getOptions()->get($key, $val);
	}

	public function getUser($id=null) {
		// Make sure we are logged in
		if($id === null && !$this->getVisitor()->getUserId()) {
			return array();
		}

		$userId = $id !== null ? $id : $this->getVisitor()->getUserId();
		return \XenForo_Model::create('\XenForo_Model_User')->getFullUserById($userId);
	}

	public function isLoggedIn() {
		return $this->getVisitor()->getUserId();
	}

	public function verifyUsername($username, $userId=null) {
		// standardize white space in names
		$username = preg_replace('/\s+/u', ' ', $username);
		try
		{
			$newName = preg_replace('/\v+/u', ' ', $username);
			if (is_string($newName))
			{
				$username = $newName;
			}
		}
		catch (Exception $e) {}

		$username = trim($username);

		$usernameLength = utf8_strlen($username);
		$minLength = $this->getOption('usernameLength', 'min');
		$maxLength = $this->getOption('usernameLength', 'max');

		if ($minLength > 0 && $usernameLength < $minLength)
		{
			return new \XenForo_Phrase('please_enter_name_that_is_at_least_x_characters_long', array('count' => $minLength));
		}

		if ($maxLength > 0 && $usernameLength > $maxLength)
		{
			return new \XenForo_Phrase('please_enter_name_that_is_at_most_x_characters_long', array('count' => $maxLength));
		}

		$disallowedNames = preg_split('/\r?\n/', $this->getOption('usernameValidation', 'disallowedNames'));
		if ($disallowedNames)
		{
			foreach ($disallowedNames AS $name)
			{
				$name = trim($name);
				if ($name === '')
				{
					continue;
				}
				if (stripos($username, $name) !== false)
				{
					return new \XenForo_Phrase('please_enter_another_name_disallowed_words');
				}
			}
		}

		$matchRegex = $this->getOption('usernameValidation', 'matchRegex');
		if ($matchRegex)
		{
			$matchRegex = str_replace('#', '\\#', $matchRegex); // escape delim only
			if (!preg_match('#' . $matchRegex . '#i', $username))
			{
				return new \XenForo_Phrase('please_enter_another_name_required_format');
			}
		}

		$censoredUserName = \XenForo_Helper_String::censorString($username);
		if ($censoredUserName !== $username)
		{
			return new \XenForo_Phrase('please_enter_name_that_does_not_contain_any_censored_words');
		}

		// ignore check if unicode properties aren't compiled
		try
		{
			if (@preg_match("/\p{C}/u", $username))
			{
				return new \XenForo_Phrase('please_enter_name_without_using_control_characters');
			}
		}
		catch (Exception $e) {}

		if (strpos($username, ',') !== false)
		{
			return new \XenForo_Phrase('please_enter_name_that_does_not_contain_comma');
		}

		if (\Zend_Validate::is($username, 'EmailAddress'))
		{
			return new \XenForo_Phrase('please_enter_name_that_does_not_resemble_an_email_address');
		}

		$existingUser = \XenForo_Model::create('\XenForo_Model_User')->getUserByName($username);
		if($existingUser && (!$userId || ($userId && $userId != $existingUser['user_id']))) {
			return new \XenForo_Phrase('usernames_must_be_unique');
		}

		// compare against romanized name to help reduce confusable issues
		$romanized = utf8_deaccent(utf8_romanize($username));
		if ($romanized != $username)
		{
			$existingUser = \XenForo_Model::create('\XenForo_Model_User')->getUserByName($romanized);
			if($existingUser && (!$userId || ($userId && $userId != $existingUser['user_id']))) {
				return new \XenForo_Phrase('usernames_must_be_unique');
			}
		}

		return true;
	}

	public function verifyEmail($email, $userId=null) {
		if(!\Zend_Validate::is($email, 'EmailAddress')) {
			return new \XenForo_Phrase('please_enter_valid_email');
		}

		$existingUser = \XenForo_Model::create('\XenForo_Model_User')->getUserByEmail($email);
		if($existingUser && (!$userId || ($userId && $userId != $existingUser['user_id']))) {
			return new \XenForo_Phrase('email_addresses_must_be_unique');
		}

		if(\XenForo_Helper_Email::isEmailBanned($email)) {
			return new \XenForo_Phrase('email_address_you_entered_has_been_banned_by_administrator');
		}

		return true;
	}

	/**
	 * Sets the user's password.
	 *
	 * @param string $password
	 * @param string|false $passwordConfirm If a string, ensures that the password and the confirm are the same
	 * @param \XenForo_Authentication_Abstract|null $auth Auth object to generate the password (or null to use default)
	 * @param boolean If true, do not accept an empty password
	 *
	 * @return boolean
	 */
	public function setPassword($password, $passwordConfirm = false, \XenForo_Authentication_Abstract $auth = null, $requirePassword = false)
	{
		if ($requirePassword && $password === '')
		{
			return new \XenForo_Phrase('please_enter_valid_password');
		}

		if ($passwordConfirm !== false && $password !== $passwordConfirm)
		{
			return new \XenForo_Phrase('passwords_did_not_match');
		}

		if (!$auth)
		{
			$auth = \XenForo_Authentication_Abstract::createDefault();
		}

		$authData = $auth->generate($password);
		if (!$authData)
		{
			return new \XenForo_Phrase('please_enter_valid_password');
		}

		return array('scheme_class' => $auth->getClassName(), 'data' => $authData);
	}

	public function addUser($email, $username, $password, $additional=array()) {
		// Verify email
		$verifyEmail = $this->verifyEmail($email);
		if($verifyEmail !== true) {
			return $verifyEmail;
		}

		// Verify username
		$verifyUsername = $this->verifyUsername($username);
		if($verifyUsername !== true) {
			return $verifyUsername;
		}

		// Verify Password
		$userPassword = $this->setPassword($password);
		if(is_object($userPassword) && get_class($userPassword) == '\XenForo_Phrase') {
			return $userPassword;
		}

		// Replace spaces
		$username = str_replace(' ', '_', $username);
 
		// Create writer object
		$writer = \XenForo_DataWriter::create('\XenForo_DataWriter_User');
		$info = array_merge($additional, array(
			'username' => $username,
			'email' => $email,
			'user_group_id' => \XenForo_Model_User::$defaultRegisteredGroupId,
			'language_id' => $this->getVisitor()->get('language_id'),
		));

		$writer->advanceRegistrationUserState();

		$writer->bulkSet($info);

		// Set user password
		$writer->set('scheme_class', $userPassword['scheme_class']);
		$writer->set('data', $userPassword['data'], 'xf_user_authenticate');

		// Save user
		$writer->save();
		$user = $writer->getMergedData();
		
		if(!$user['user_id']) {
			return new \XenForo_Phrase('user_was_not_created');
		}

		// log the ip of the user registering
		\XenForo_Model_Ip::log($user['user_id'], 'user', $user['user_id'], 'register');

		if ($user['user_state'] == 'email_confirm') {
			\XenForo_Model::create('\XenForo_Model_UserConfirmation')->sendEmailConfirmation($user);
		}

		return $user['user_id'];
	}

	public function validateLogin($email, $password, $remember=false, $doLogin=false) {
		// Init
		$loginModel = \XenForo_Model::create('\XenForo_Model_Login');
		$userModel = \XenForo_Model::create('\XenForo_Model_User');
		$hasError = null;

		// Validate user info
		$user = $userModel->validateAuthentication($email, $password, $hasError);
		if(!$user) {
			$loginModel->logLoginAttempt($email);
			return new \XenForo_Phrase($hasError);
		}

		// Clear login attempts
		$loginModel->clearLoginAttempts($email);

		// Login
		if($doLogin) {
			return $this->login($user, $remember);
		}
		 
		// This just validates the login info
		// so a bool is a good idea to return here
		return true;
	}

	public function login($user, $remember=false) {
		$userModel = \XenForo_Model::create('\XenForo_Model_User');

		// Set cookie if needed
		if($remember) {
			$userModel->setUserRememberCookie($user);
		}

		// Log IP
		\XenForo_Model_Ip::log($user, 'user', $user, 'login');

		// delete current session
		$userModel->deleteSessionActivity(0, $_SERVER['REMOTE_ADDR']);

		$this->getSession()->changeUserId($user);
		$this->getVisitor()->setup($user);

		return $user;
	}

	public function adminLogout() {
		$session = new \XenForo_Session(array('admin' => true));
		$session->start();
		if ($session->get('user_id') == $this->getVisitor()->getUserId()) {
			return $session->delete();
		}

		return true;
	}

	public function logout() {
		// Check if we are an admin
		if($this->getVisitor()->get('is_admin')) {
			// Logout admin
			$this->adminLogout();
		}

		// Logout user
		\XenForo_Model::create('\XenForo_Model_Session')->processLastActivityUpdateForLogOut($this->getVisitor()->getUserId());
		$this->getSession()->delete();

		\XenForo_Helper_Cookie::deleteAllCookies(array('session'), array('user' => array('httpOnly' => false)));
		$this->getVisitor()->setup(0);

		return true;
	}

	public function getForumById($id, $fetchOptions=array()) {
		return \XenForo_Model::create('\XenForo_Model_Forum')->getForumById($id, $fetchOptions);
	}

	public function getForumsByIds($ids, $fetchOptions=array()) {
		return \XenForo_Model::create('\XenForo_Model_Forum')->getForumsByIds($ids, $fetchOptions);
	}

	public function getForums(array $conditions = array(), array $fetchOptions = array()) {
		return \XenForo_Model::create('\XenForo_Model_Forum')->getForums($conditions, $fetchOptions);
	}

	public function getThreadsByIds($ids, $fetchOptions=array()) {
		return \XenForo_Model::create('\XenForo_Model_Thread')->getThreadsByIds($ids, $fetchOptions);
	}

	public function getThreadById($id, $fetchOptions=array()) {
		return \XenForo_Model::create('\XenForo_Model_Thread')->getThreadById($id, $fetchOptions);
	}

	public function getThreads(array $conditions, array $fetchOptions = array()) {
		return \XenForo_Model::create('\XenForo_Model_Thread')->getThreads($conditions, $fetchOptions);
	}

	public function renderTemplate($name, $params=array(), $styleId=null, $languageId=null) {
		// user
		$user = $this->getUser();

		// Template
		$template = new \XenForo_Template_Public($name, $params);
		$template->setStyleId(($styleId!==null ? $styleId : $user['style_id']));
		$template->setLanguageId(($languageId!==null ? $languageId : $user['language_id']));

		return $template->render();
	}

	public function renderAdminTemplate($name, $params=array(), $styleId=null, $languageId=null) {
		// user
		$user = $this->getUser();

		// Template
		$template = new \XenForo_Template_Admin($name, $params);
		$template->setStyleId(($styleId!==null ? $styleId : $user['style_id']));
		$template->setLanguageId(($languageId!==null ? $languageId : $user['language_id']));

		return $template->render();
	}
}