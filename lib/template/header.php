<?php
jirafeau_send_security_headers(true);
header('Content-Type: text/html; charset=utf-8');
header('x-ua-compatible: ie=edge');

$page_title = (true === empty($cfg['title'])) ? t('JI_WEB_RE') : $cfg['title'];
$style_name = jirafeau_is_valid_style_name($cfg['style']) ? $cfg['style'] : 'courgette';
?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title><?php echo jirafeau_escape($page_title); ?></title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link id="shortcut_icon" rel="shortcut icon" href="<?php echo 'media/' . jirafeau_escape($style_name) . '/favicon.ico'; ?>">
  <link id="stylesheet" rel="stylesheet" href="<?php echo 'media/' . jirafeau_escape($style_name) . '/style.css.php'; ?>" type="text/css" />
</head>
<body>
<script type="text/javascript" src="<?php echo 'lib/functions.js.php'; ?>"></script>
<script type="text/javascript" lang="Javascript">color_scheme_preferences();</script>
<div id="content">
  <h1>
    <a href="./">
      <?php echo jirafeau_escape($page_title); ?>
    </a>
  </h1>
