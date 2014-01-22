<?php

require_once('XenForoSDK.php');
$sdk = new XenForoSDK;

$loggedIn = $sdk->isLoggedIn();
if($loggedIn) {
	echo 'Logged In';
} else {
	echo 'Guest';
}

// Validate loing
$valid = $sdk->validateLogin('test@test.com', 'password', $rememberMe, $loginUserIfSuccessful);

if($valid !== true) {
	echo $valid; // will display the error
}

// Login user
$user = $sdk->login($userId, $rememberMe); // no validation

// Logout
$sdk->logout();

// Hash password
$passwrod = $sdk->setPassword('test123', 'passward_confirm'); // returns array scheme_class and data

// Add new user
$newUser = $sdk->addUser('test@test.com', 'myusername', 'mypassword', array('someotherdata' => 'someothervalue'));
if(is_object($newUser)) {
	// user was not created show error
	echo $newUser;
} else {
	// user created, $newUser holds id
	echo 'New User ID: ' . $newUser;
}

// Get all forums
$forums = $sdk->getForums();

// Get one forum
$forum = $sdk->getForumById(2);

// Get all threads
$threads = $sdk->getThreads(array()); // will show all so make sure to add conditions

// Get one thread
$thread = $sdk->getThreadById(2);

// Get current user
$user = $sdk->getUser();

// Get other user info
$user = $sdk->getUser(2);

// Get current visitor/session info
$visitor = $sdk->getVisitor();
$session = $sdk->getSession();

// Get options/option
$options = $sdk->getOptions();
$option = $sdk->getOption($key);

// Render public/admin template
$output = $sdk->renderPublicTemplate('template_name', array $params);
$output = $sdk->renderAdminTemplate('template_name', array $params);


