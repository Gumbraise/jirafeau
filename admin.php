<?php
/*
 *  Jirafeau, your web file repository
 *  Copyright (C) 2008  Julien "axolotl" BERNARD <axolotl@magieeternelle.org>
 *  Copyright (C) 2015  Jerome Jutteau <jerome@jutteau.fr>
 *  Copyright (C) 2024  Jirafeau project <https://gitlab.com/jirafeau> (see AUTHORS.md)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
define('JIRAFEAU_ROOT', dirname(__FILE__) . '/');

require(JIRAFEAU_ROOT . 'lib/settings.php');
require(JIRAFEAU_ROOT . 'lib/functions.php');
require(JIRAFEAU_ROOT . 'lib/lang.php');

jirafeau_configure_session();
session_start();

/* Check if installation is OK. */
if (file_exists(JIRAFEAU_ROOT . 'install.php')
    && !file_exists(JIRAFEAU_ROOT . 'lib/config.local.php')) {
    header('Location: install.php');
    exit;
}

/* If called from CLI, no password or graphical interface */
if (php_sapi_name() == "cli") {
    if ($cfg['installation_done'] == false) {
        die("Installation not completed yet.\n");
    }
    if ((count($argv) > 1) && $argv[1] == 'clean_expired') {
        $total = jirafeau_admin_clean();
        echo "$total expired files deleted.\n";
    } elseif ((count($argv) > 1) && $argv[1] == 'clean_async') {
        $total = jirafeau_admin_clean_async();
        echo "$total old unfinished transfers deleted.\n";
    } else {
        die("No command found. Should be admin.php <clean_expired|clean_async>.\n");
    }
}
/* Second check: Challenge by IP */
elseif (true === jirafeau_challenge_admin_ip($cfg, get_ip_address($cfg))) {
    /* Disable admin interface if we have a empty admin password. */
    if (empty($cfg['admin_password']) && empty($cfg['admin_http_auth_user'])) {
        require(JIRAFEAU_ROOT . 'lib/template/header.php');
        echo '<div class="error"><p>'.
           t('NO_ADMIN') .
           '</p></div>';
        require(JIRAFEAU_ROOT.'lib/template/footer.php');
        exit;
    }

    /* Logout if requested. */
    if (jirafeau_admin_is_authenticated() && isset($_POST['action']) && (strcmp($_POST['action'], 'logout') == 0)) {
        jirafeau_admin_require_csrf_or_exit();
        jirafeau_session_end();
        header('Location: admin.php');
        exit;
    }

    if (!jirafeau_admin_is_authenticated()) {
        $authed = false;
        /* Test HTTP authentication. */
        if (!empty($cfg['admin_http_auth_user']) && isset($_SERVER['PHP_AUTH_USER'])) {
            $http_users = is_array($cfg['admin_http_auth_user'])
                ? $cfg['admin_http_auth_user']
                : array($cfg['admin_http_auth_user']);
            if (in_array($_SERVER['PHP_AUTH_USER'], $http_users, true)) {
                jirafeau_admin_session_start();
                $authed = true;
            }
        }
        /* Test web password authentication. */
        if (!$authed && !empty($cfg['admin_password']) && isset($_POST['admin_password']) && is_string($_POST['admin_password'])) {
            if (jirafeau_auth_is_blocked('admin_login', $cfg)) {
                http_response_code(429);
                require(JIRAFEAU_ROOT . 'lib/template/header.php');
                jirafeau_show_page_error('BAD_PSW', 'BAD_PSW_BODY', $cfg, 'denied', false);
                require(JIRAFEAU_ROOT.'lib/template/footer.php');
                exit;
            }
            if (jirafeau_verify_admin_password($_POST['admin_password'], $cfg['admin_password'])) {
                jirafeau_auth_clear_failures('admin_login', $cfg);
                if (jirafeau_admin_password_needs_rehash($cfg['admin_password'])) {
                    $cfg['admin_password'] = jirafeau_hash_admin_password($_POST['admin_password']);
                    jirafeau_export_cfg($cfg);
                }
                jirafeau_admin_session_start();
                $authed = true;
            } else {
                jirafeau_auth_register_failure('admin_login', $cfg);
                require(JIRAFEAU_ROOT . 'lib/template/header.php');
                echo '<div class="error"><p>'. t('BAD_PSW') . '</p></div>';
                require(JIRAFEAU_ROOT.'lib/template/footer.php');
                exit;
            }
        }
        /* Admin password prompt form. */
        if (!$authed) {
            require(JIRAFEAU_ROOT . 'lib/template/header.php'); ?>
          <form method="post" class="form login">
          <fieldset>
              <table>
              <tr>
                  <td class = "label"><label for = "enter_password">
                  <?php echo t('ADMIN_PSW') . ':'; ?></label>
                  </td>
              </tr>
              <tr>
                  <td class = "field"><input type = "password"
                  name = "admin_password" id = "admin_password"
                  size = "40" autocomplete = "current-password" />
                  </td>
              </tr>
              <tr class = "nav">
                  <td class = "nav next">
                  <input type = "submit" name = "key" value =
                  "<?php echo t('LOGIN'); ?>" />
                  </td>
              </tr>
              </table>
          </fieldset>
          </form>
          <?php
          require(JIRAFEAU_ROOT.'lib/template/footer.php');
            exit;
        }
    }

    /* Operations may take a long time.
     * Be sure PHP's safe mode is off.
     */
    @set_time_limit(0);

    /* Show admin interface if not downloading a file. */
    if (!(isset($_POST['action']) && strcmp($_POST['action'], 'download') == 0)) {
        require(JIRAFEAU_ROOT . 'lib/template/header.php'); ?><h2><?php echo t('ADMIN_INTERFACE'); ?></h2><?php
        ?><h2>(version <?php echo JIRAFEAU_VERSION ?>)</h2><?php

        if ($cfg['enable_crypt'] && !(extension_loaded('sodium'))) {
            echo '<div class="error"><p>'.t('SODIUM_UNAVAILABLE').'</p></div>';
        }

        ?><div id = "admin">
          <fieldset><legend><?php echo t('ACTIONS'); ?></legend>
          <table>
          <form method="post">
          <tr>
              <input type = "hidden" name = "action" value = "clean"/>
              <?php echo jirafeau_admin_csrf_field() ?>
              <td class = "info">
                  <?php echo t('CLEAN_EXPIRED'); ?>
              </td>
              <td></td>
              <td>
                  <input type = "submit" value = "<?php echo t('CLEAN'); ?>" />
              </td>
          </tr>
          </form>
          <form method="post">
          <tr>
              <input type = "hidden" name = "action" value = "clean_async"/>
              <?php echo jirafeau_admin_csrf_field() ?>
              <td class = "info">
                  <?php echo t('CLEAN_INCOMPLETE'); ?>
              </td>
              <td></td>
              <td>
                  <input type = "submit" value = "<?php echo t('CLEAN'); ?>" />
              </td>
          </tr>
          </form>
          <form method="post">
          <tr>
              <input type = "hidden" name = "action" value = "list"/>
              <?php echo jirafeau_admin_csrf_field() ?>
              <td class = "info">
                  <?php echo t('LIST_FILES'); ?>
              </td>
              <td></td>
              <td>
                  <input type = "submit" value = "<?php echo t('LIST'); ?>" />
              </td>
          </tr>
          </form>
          <form method="post">
              <tr>
                  <input type = "hidden" name = "action" value = "size"/>
                  <?php echo jirafeau_admin_csrf_field() ?>
                  <td class = "info">
                      <?php echo t('SIZE_DATA'); ?>
                  </td>
                  <td></td>
                  <td>
                      <input type = "submit" value = "<?php echo t('SIZE'); ?>" />
                  </td>
              </tr>
          </form>
          <form method="post">
          <tr>
              <input type = "hidden" name = "action" value = "search_by_name"/>
              <?php echo jirafeau_admin_csrf_field() ?>
              <td class = "info">
                  <?php echo t('SEARCH_NAME'); ?>
              </td>
              <td>
                  <input type = "text" name = "name" id = "name"/>
              </td>
              <td>
                  <input type = "submit" value = "<?php echo t('SEARCH'); ?>" />
              </td>
          </tr>
          </form>
          <form method="post">
          <tr>
              <input type = "hidden" name = "action" value = "search_by_file_hash"/>
              <?php echo jirafeau_admin_csrf_field() ?>
              <td class = "info">
                  <?php echo t('SEARH_BY_HASH'); ?>
              </td>
              <td>
                  <input type = "text" name = "hash" id = "hash"/>
              </td>
              <td>
                  <input type = "submit" value = "<?php echo t('SEARCH'); ?>" />
              </td>
          </tr>
          </form>
          <form method="post">
          <tr>
              <input type = "hidden" name = "action" value = "search_link"/>
              <?php echo jirafeau_admin_csrf_field() ?>
              <td class = "info">
                  <?php echo t('SEARCH_LINK'); ?>
              </td>
              <td>
                  <input type = "text" name = "link" id = "link"/>
              </td>
              <td>
                  <input type = "submit" value = "<?php echo t('SEARCH'); ?>" />
              </td>
          </tr>
          </form>
          <form method="post">
          <tr>
              <input type = "hidden" name = "action" value = "bug_report_info"/>
              <?php echo jirafeau_admin_csrf_field() ?>
              <td class = "info">
                  <?php echo t('REPORTING_AN_ISSUE'); ?>
              </td>
              <td></td>
              <td>
                  <input type = "submit" value = "<?php echo t('INFO'); ?>" />
              </td>
          </tr>
          </form>
          </table>
          <form method="post">
              <input type = "hidden" name = "action" value = "logout" />
              <?php echo jirafeau_admin_csrf_field() ?>
              <input type = "submit" value = "<?php echo t('LOGOUT'); ?>" />
          </form>
          </fieldset></div><?php
    }

    /* Check for actions — CSRF required for every state-changing POST. */
    if (isset($_POST['action'])) {
        jirafeau_admin_require_csrf_or_exit();

        if (strcmp($_POST['action'], 'clean') == 0) {
            $total = jirafeau_admin_clean();
            echo '<div class="message">' . NL;
            echo '<p>';
            echo t('CLEANED_FILES_CNT') . ' : ' . $total;
            echo '</p></div>';
        } elseif (strcmp($_POST['action'], 'clean_async') == 0) {
            $total = jirafeau_admin_clean_async();
            echo '<div class="message">' . NL;
            echo '<p>';
            echo t('CLEANED_FILES_CNT') . ' : ' . $total;
            echo '</p></div>';
        } elseif (strcmp($_POST['action'], 'size') == 0) {
            $size = jirafeau_dir_size($cfg['var_root']);
            $human_size = jirafeau_human_size($size);
            echo '<div class="message">' . NL;
            echo '<p>' . t('SIZE_DATA') . ': ' . $human_size .'</p>';
            echo '</div>';
        } elseif (strcmp($_POST['action'], 'list') == 0) {
            jirafeau_admin_list("", "", "");
        } elseif (strcmp($_POST['action'], 'search_by_name') == 0) {
            $name = isset($_POST['name']) && is_string($_POST['name']) ? $_POST['name'] : '';
            jirafeau_admin_list($name, "", "");
        } elseif (strcmp($_POST['action'], 'search_by_file_hash') == 0) {
            $hash = isset($_POST['hash']) && is_string($_POST['hash']) ? $_POST['hash'] : '';
            jirafeau_admin_list("", $hash, "");
        } elseif (strcmp($_POST['action'], 'search_link') == 0) {
            $link = isset($_POST['link']) && is_string($_POST['link']) ? $_POST['link'] : '';
            jirafeau_admin_list("", "", $link);
        } elseif (strcmp($_POST['action'], 'delete_link') == 0) {
            if (isset($_POST['link']) && is_string($_POST['link'])) {
                jirafeau_delete_link($_POST['link']);
            }
            echo '<div class="message">' . NL;
            echo '<p>' . t('LINK_DELETED') . '</p></div>';
        } elseif (strcmp($_POST['action'], 'delete_file') == 0) {
            $count = 0;
            if (isset($_POST['hash']) && is_string($_POST['hash'])) {
                $count = jirafeau_delete_file($_POST['hash']);
            }
            echo '<div class="message">' . NL;
            echo '<p>' . t('DELETED_LINKS') . ' : ' . $count . '</p></div>';
        } elseif (strcmp($_POST['action'], 'download') == 0) {
            if (!isset($_POST['link']) || !is_string($_POST['link'])) {
                exit;
            }
            $l = jirafeau_get_link($_POST['link']);
            if (!count($l)) {
                return;
            }
            $p = s2p($l['hash']);
            jirafeau_send_security_headers(false);
            header('Content-Length: ' . $l['file_size']);
            header('Content-Type: ' . jirafeau_sanitize_mime_type($l['mime_type']));
            jirafeau_content_disposition_header($l['file_name'], true);
            if (file_exists(VAR_FILES . $p . $l['hash'])) {
                $r = fopen(VAR_FILES . $p . $l['hash'], 'r');
                while (!feof($r)) {
                    print fread($r, 1024);
                }
                fclose($r);
            }
            exit;
        } elseif (strcmp($_POST['action'], 'bug_report_info') == 0) {
            echo jirafeau_admin_bug_report($cfg);
        }
    }

    require(JIRAFEAU_ROOT.'lib/template/footer.php');
} else {
    require(JIRAFEAU_ROOT . 'lib/template/header.php');
    jirafeau_fatal_error(t('ACCESS_KO'), $cfg);
}
?>
