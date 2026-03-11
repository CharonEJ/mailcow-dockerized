<?php
/**
 * User-Managed Permanent Aliases
 *
 * Allows regular mailbox users to create permanent email aliases following
 * the pattern {prefix}-{localpart}@{domain} or {prefix}-{synonym}@{domain}.
 *
 * Functions:
 *   get_user_alias_config($username)
 *   set_user_synonym($username, $synonym)
 *   validate_user_alias_format($alias_local, $allowed_locals)
 *   list_user_aliases($username)
 *   add_user_alias($username, $_data)
 *   delete_user_alias($username, $_data)
 */

/**
 * Retrieve the user alias configuration (synonym, synonym_set flag).
 */
function get_user_alias_config($username) {
  global $pdo;
  $stmt = $pdo->prepare("SELECT `username`, `synonym`, `domain`, `synonym_set`, `created`
    FROM `user_alias_config`
    WHERE `username` = :username");
  $stmt->execute(array(':username' => $username));
  $row = $stmt->fetch(PDO::FETCH_ASSOC);
  if (!$row) {
    // Return defaults when no record exists yet
    $domain = substr(strstr($username, '@'), 1);
    return array(
      'username'    => $username,
      'synonym'     => null,
      'domain'      => $domain,
      'synonym_set' => 0,
      'created'     => null
    );
  }
  return $row;
}

/**
 * Validate that an alias local-part matches the pattern {prefix}-{allowed_local}.
 * Prefix must be at least 1 character, only [a-z0-9-] allowed.
 */
function validate_user_alias_format($alias_local, $allowed_locals) {
  foreach ($allowed_locals as $local) {
    $escaped = preg_quote($local, '/');
    // Pattern: [a-z0-9][a-z0-9-]*-{local}
    // Ensures prefix starts with a letter/digit and ends with -{local}
    if (preg_match('/^[a-z0-9][a-z0-9-]*-' . $escaped . '$/', $alias_local)) {
      return true;
    }
  }
  return false;
}

/**
 * Set a one-time synonym for the user.
 * Once set (synonym_set=1), only an admin can change it.
 */
function set_user_synonym($username, $synonym) {
  global $pdo;

  // Validate format: 2-20 chars, only [a-z0-9-], must start with letter/digit
  if (!preg_match('/^[a-z0-9][a-z0-9-]{1,19}$/', $synonym)) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $synonym),
      'msg'  => 'user_alias_synonym_invalid_format'
    );
    return false;
  }

  // Look up user's domain
  $stmt = $pdo->prepare("SELECT `domain` FROM `mailbox` WHERE `username` = :username");
  $stmt->execute(array(':username' => $username));
  $row = $stmt->fetch(PDO::FETCH_ASSOC);
  if (!$row) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $synonym),
      'msg'  => 'mailbox_not_found'
    );
    return false;
  }
  $domain = $row['domain'];

  // Ensure synonym has not already been set
  $config = get_user_alias_config($username);
  if (intval($config['synonym_set']) === 1) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $synonym),
      'msg'  => 'user_alias_synonym_already_set'
    );
    return false;
  }

  // Synonym must not collide with an existing mailbox in this domain
  $stmt = $pdo->prepare("SELECT `username` FROM `mailbox`
    WHERE `username` = :addr AND `domain` = :domain");
  $stmt->execute(array(
    ':addr'   => $synonym . '@' . $domain,
    ':domain' => $domain
  ));
  if ($stmt->fetch()) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $synonym),
      'msg'  => 'user_alias_synonym_not_unique'
    );
    return false;
  }

  // Synonym must not collide with an existing alias in this domain
  $stmt = $pdo->prepare("SELECT `address` FROM `alias`
    WHERE `address` = :addr AND `domain` = :domain");
  $stmt->execute(array(
    ':addr'   => $synonym . '@' . $domain,
    ':domain' => $domain
  ));
  if ($stmt->fetch()) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $synonym),
      'msg'  => 'user_alias_synonym_not_unique'
    );
    return false;
  }

  // Synonym must not collide with an existing synonym in this domain
  $stmt = $pdo->prepare("SELECT `username` FROM `user_alias_config`
    WHERE `synonym` = :synonym AND `domain` = :domain");
  $stmt->execute(array(
    ':synonym' => $synonym,
    ':domain'  => $domain
  ));
  if ($stmt->fetch()) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $synonym),
      'msg'  => 'user_alias_synonym_not_unique'
    );
    return false;
  }

  // Persist to user_alias_config
  $stmt = $pdo->prepare("INSERT INTO `user_alias_config`
      (`username`, `synonym`, `domain`, `synonym_set`)
    VALUES (:username, :synonym, :domain, 1)
    ON DUPLICATE KEY UPDATE
      `synonym` = :synonym2,
      `domain` = :domain2,
      `synonym_set` = 1");
  $stmt->execute(array(
    ':username' => $username,
    ':synonym'  => $synonym,
    ':domain'   => $domain,
    ':synonym2' => $synonym,
    ':domain2'  => $domain
  ));

  // Create the forwarding alias synonym@domain → username
  mailbox('add', 'alias', array(
    'address'         => $synonym . '@' . $domain,
    'goto'            => $username,
    'active'          => 1,
    'internal'        => 0,
    'sender_allowed'  => 0,
    'sogo_visible'    => 0,
    'goto_null'       => 0,
    'goto_spam'       => 0,
    'goto_ham'        => 0,
    'private_comment' => '',
    'public_comment'  => ''
  ));

  $_SESSION['return'][] = array(
    'type' => 'success',
    'log'  => array(__FUNCTION__, $username, $synonym),
    'msg'  => 'user_alias_synonym_set'
  );
  return true;
}

/**
 * Return all user-managed aliases for the given mailbox user.
 * Only aliases matching the {prefix}-{local}@{domain} pattern are returned.
 */
function list_user_aliases($username) {
  global $pdo;

  $local_part = strstr($username, '@', true);
  $domain     = substr(strstr($username, '@'), 1);

  $config  = get_user_alias_config($username);
  $synonym = $config['synonym'];

  $allowed_locals = array($local_part);
  if ($synonym) {
    $allowed_locals[] = $synonym;
  }

  $stmt = $pdo->prepare("SELECT `id`, `address`, `goto`, `active`, `created`, `modified`
    FROM `alias`
    WHERE `goto` = :username
      AND `domain` = :domain
      AND `address` NOT LIKE '@%'
    ORDER BY `address` ASC");
  $stmt->execute(array(
    ':username' => $username,
    ':domain'   => $domain
  ));
  $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

  $user_aliases = array();
  foreach ($rows as $row) {
    $alias_local = strstr($row['address'], '@', true);
    if (validate_user_alias_format($alias_local, $allowed_locals)) {
      $user_aliases[] = $row;
    }
  }
  return $user_aliases;
}

/**
 * Add a new user-managed alias.
 * $_data must contain 'address' with the full alias address.
 */
function add_user_alias($username, $_data) {
  global $pdo;

  // ACL check
  if (!isset($_SESSION['acl']['user_managed_aliases']) || intval($_SESSION['acl']['user_managed_aliases']) != 1) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $_data),
      'msg'  => 'access_denied'
    );
    return false;
  }

  $local_part = strstr($username, '@', true);
  $domain     = substr(strstr($username, '@'), 1);

  $config  = get_user_alias_config($username);
  $synonym = $config['synonym'];

  $allowed_locals = array($local_part);
  if ($synonym) {
    $allowed_locals[] = $synonym;
  }

  // Normalise and validate the alias address
  $alias_address = strtolower(trim((string)$_data['address']));

  if (strlen($alias_address) > 253) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $_data),
      'msg'  => 'user_alias_address_too_long'
    );
    return false;
  }

  if (!filter_var($alias_address, FILTER_VALIDATE_EMAIL)) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $_data),
      'msg'  => 'user_alias_invalid_address'
    );
    return false;
  }

  // Domain of the alias must match user's own domain
  $alias_domain = idn_to_ascii(substr(strstr($alias_address, '@'), 1), 0, INTL_IDNA_VARIANT_UTS46);
  if ($alias_domain !== $domain) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $_data),
      'msg'  => 'user_alias_domain_mismatch'
    );
    return false;
  }

  // Validate the format: {prefix}-{local_or_synonym}@{domain}
  $alias_local = strstr($alias_address, '@', true);
  if (!validate_user_alias_format($alias_local, $allowed_locals)) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $_data),
      'msg'  => 'user_alias_invalid_format'
    );
    return false;
  }

  // Enforce per-user alias count limit
  $existing  = list_user_aliases($username);
  $max_count = 50;
  if (count($existing) >= $max_count) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $_data),
      'msg'  => array('user_alias_max_count', $max_count)
    );
    return false;
  }

  return mailbox('add', 'alias', array(
    'address'         => $alias_address,
    'goto'            => $username,
    'active'          => 1,
    'internal'        => 0,
    'sender_allowed'  => 0,
    'sogo_visible'    => 0,
    'goto_null'       => 0,
    'goto_spam'       => 0,
    'goto_ham'        => 0,
    'private_comment' => '',
    'public_comment'  => ''
  ));
}

/**
 * Delete one or more user-managed aliases.
 * $_data must contain 'id' (scalar or array of alias IDs).
 * Only aliases that belong to the user and match the pattern may be deleted.
 */
function delete_user_alias($username, $_data) {
  global $pdo;

  // ACL check
  if (!isset($_SESSION['acl']['user_managed_aliases']) || intval($_SESSION['acl']['user_managed_aliases']) != 1) {
    $_SESSION['return'][] = array(
      'type' => 'danger',
      'log'  => array(__FUNCTION__, $username, $_data),
      'msg'  => 'access_denied'
    );
    return false;
  }

  $local_part = strstr($username, '@', true);

  $config  = get_user_alias_config($username);
  $synonym = $config['synonym'];

  $allowed_locals = array($local_part);
  if ($synonym) {
    $allowed_locals[] = $synonym;
  }

  $items = (array)$_data['id'];

  foreach ($items as $alias_id) {
    $alias_id = intval($alias_id);

    $stmt = $pdo->prepare("SELECT `id`, `address`, `goto`, `domain`
      FROM `alias`
      WHERE `id` = :id");
    $stmt->execute(array(':id' => $alias_id));
    $alias = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$alias) {
      $_SESSION['return'][] = array(
        'type' => 'danger',
        'log'  => array(__FUNCTION__, $username, $_data),
        'msg'  => array('user_alias_not_found', $alias_id)
      );
      continue;
    }

    // The alias must forward to this user
    if ($alias['goto'] !== $username) {
      $_SESSION['return'][] = array(
        'type' => 'danger',
        'log'  => array(__FUNCTION__, $username, $_data),
        'msg'  => 'access_denied'
      );
      continue;
    }

    // The alias address must match the user's pattern
    $alias_local = strstr($alias['address'], '@', true);
    if (!validate_user_alias_format($alias_local, $allowed_locals)) {
      $_SESSION['return'][] = array(
        'type' => 'danger',
        'log'  => array(__FUNCTION__, $username, $_data),
        'msg'  => 'access_denied'
      );
      continue;
    }

    $stmt = $pdo->prepare("DELETE FROM `alias` WHERE `id` = :id");
    $stmt->execute(array(':id' => $alias_id));

    $_SESSION['return'][] = array(
      'type' => 'success',
      'log'  => array(__FUNCTION__, $username, $alias['address']),
      'msg'  => array('alias_removed', htmlspecialchars($alias['address']))
    );
  }

  return true;
}
