<?php
/**
 * contact.php - réception du formulaire de devis www.cleanibat.fr (lot L1).
 *
 * Formulaire HTML classique (POST multipart, site/form.py + assets/js/devis.js).
 * Aucune donnée sensible dans ce fichier : la configuration (destinataire des
 * demandes = facts.LEAD_EMAIL, secret, URL du webhook Make) est lue HORS du
 * dossier public :
 *     dirname(DOCUMENT_ROOT)/cleanibat_private/config.json
 * Le même dossier reçoit leads.csv, spam.csv, make.log, rl/, tokens/,
 * photos/AAAA-MM/ (voir deploy/private/README.md). Repli, seulement si ce
 * dossier ne peut pas être créé : _private/ à côté de ce fichier, protégé par
 * un .htaccess « Require all denied ».
 *
 * Déroulé d'un POST :
 *   0. GET ?jeton=1 -> {t, h, b} (no-store) ; autre méthode que POST -> 405 ;
 *      envoi plus gros que post_max_size -> page « photos trop lourdes ».
 *   1. Nettoyage (trim, caractères de contrôle, longueurs, listes blanches ;
 *      échappement HTML à l'affichage par cb_h).
 *   2. Robots (rejet SILENCIEUX : même 303 vers /merci.html, ni email ni Make,
 *      une ligne dans spam.csv) : champ piège, jeton faux / trop rapide /
 *      expiré / rejoué, email jetable, téléphone en liste noire.
 *      Suspects (email « [À vérifier] » au gérant, jamais perdus, pas de Make) :
 *      pas de jeton (JS absent), jeton émis pour un autre navigateur, lien ou
 *      alphabet cyrillique / chinois / arabe dans les champs texte.
 *   3. Validation humaine -> page 422 aux couleurs du site si erreur.
 *      Puis limite par IP (3 envois valides / 10 min, 8 / 24 h) -> rejet silencieux
 *      (en mode test : page 429 explicite, la limite s'applique aussi).
 *   4. Photos (3 max, 8 Mo chacune, 20 Mo au total, JPEG/PNG/WebP/HEIC).
 *   5. lead_id, origine (Google Ads / Meta Ads / SEO / Autre / Direct).
 *   6. leads.csv AVANT tout envoi (statut ok / suspect / doublon / test).
 *   7. Email au gérant (HTML + texte, photos jointes).
 *   8. Redirection 303 /merci.html?ref=<lead_id>, fin de la réponse au navigateur.
 *   9. Accusé de réception au prospect (statut ok ou test, email valide), puis
 *      Make (statut ok seulement, ou ?test=make) ; échec -> email « Make KO ».
 *
 * Mode test : ?test=1 ou champ _test=1 -> sujet [TEST], statut test, pas de
 * Make. ?test=make -> sujet [TEST] et appel à Make volontaire.
 */

mb_internal_encoding('UTF-8');
date_default_timezone_set('Europe/Paris');

define('CB_PHONE_DISPLAY', '07 80 90 02 59');
define('CB_PHONE_INTL', '+33780900259');
define('CB_SITE', 'https://www.cleanibat.fr');
define('CB_PUBLIC_EMAIL', 'aymeric@cleanibat.fr');

/* =========================================================================
   Outils
   ========================================================================= */

function cb_docroot()
{
    $d = isset($_SERVER['DOCUMENT_ROOT']) ? (string) $_SERVER['DOCUMENT_ROOT'] : '';
    return $d !== '' ? rtrim($d, '/') : __DIR__;
}

/** Dossier privé (créé si besoin). Hors docroot de préférence. */
function cb_private_dir()
{
    static $dir = null;
    if ($dir !== null) {
        return $dir;
    }
    $outside = dirname(cb_docroot()) . '/cleanibat_private';
    if (is_dir($outside) || @mkdir($outside, 0700, true)) {
        if (is_writable($outside)) {
            return $dir = $outside;
        }
    }
    $inside = __DIR__ . '/_private';
    if (!is_dir($inside)) {
        @mkdir($inside, 0700, true);
    }
    if (!is_file($inside . '/.htaccess')) {
        @file_put_contents($inside . '/.htaccess', "Require all denied\n");
    }
    return $dir = $inside;
}

function cb_config()
{
    static $cfg = null;
    if ($cfg !== null) {
        return $cfg;
    }
    $loaded = array();
    foreach (array(dirname(cb_docroot()) . '/cleanibat_private/config.json', __DIR__ . '/_private/config.json') as $p) {
        if (is_file($p)) {
            $j = json_decode((string) @file_get_contents($p), true);
            if (is_array($j)) {
                $loaded = $j;
                break;
            }
        }
    }
    $cfg = array_merge(array(
        'dest' => CB_PUBLIC_EMAIL,      // à remplacer dans config.json par l'adresse du gérant (facts.LEAD_EMAIL)
        'from' => 'no-reply@cleanibat.fr',
        'from_name' => 'Cleanibat - Site web',
        'ack_from_name' => 'Cleanibat',
        'ack_reply_to' => CB_PUBLIC_EMAIL,
        'ack_email' => true,
        'make_url' => '',
        'secret' => '',
        'phone_format' => 'national',   // 'national' = « 06 12 34 56 78 » (comme avant) ; 'e164' = « +33612345678 »
        'check_dns' => true,
        'min_seconds' => 4,
        'max_seconds' => 7200,
        'rate_10min' => 3,
        'rate_24h' => 8,
        'token_max_uses' => 3,
        'dup_minutes' => 15,
    ), $loaded);
    if (!is_string($cfg['secret']) || strlen($cfg['secret']) < 16 || stripos($cfg['secret'], 'REMPLACER') !== false) {
        $cfg['secret'] = cb_fallback_secret();
    }
    if (!is_string($cfg['dest']) || !filter_var($cfg['dest'], FILTER_VALIDATE_EMAIL)) {
        $cfg['dest'] = CB_PUBLIC_EMAIL; // config absente ou modèle non rempli : on ne perd pas la demande
    }
    if (!is_string($cfg['make_url']) || !preg_match('~^https?://~', $cfg['make_url'])) {
        $cfg['make_url'] = '';
    }
    return $cfg;
}

/** Secret de repli (si config.json n'en fournit pas) : généré une fois, stocké dans le dossier privé. */
function cb_fallback_secret()
{
    $f = cb_private_dir() . '/.secret';
    $s = is_file($f) ? trim((string) @file_get_contents($f)) : '';
    if (strlen($s) < 32) {
        $s = bin2hex(random_bytes(32));
        @file_put_contents($f, $s, LOCK_EX);
        @chmod($f, 0600);
    }
    return $s;
}

function cb_ip()
{
    return isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
}

function cb_ua()
{
    return isset($_SERVER['HTTP_USER_AGENT']) ? substr((string) $_SERVER['HTTP_USER_AGENT'], 0, 400) : '';
}

function cb_ip_hash()
{
    $c = cb_config();
    return sha1(cb_ip() . $c['secret']);
}

function cb_sig($t)
{
    $c = cb_config();
    return hash_hmac('sha256', (string) $t, $c['secret']);
}

/**
 * Signature liée au navigateur (User-Agent). L'IP n'y entre pas : elle change
 * souvent sur mobile (wifi/4G, relais privé iCloud, IPv6/IPv4). Le rejeu reste
 * bloqué par token_max_uses, la signature et l'âge du jeton.
 */
function cb_bind($t)
{
    $c = cb_config();
    return hash_hmac('sha256', (string) $t . '|' . sha1(cb_ua()), $c['secret']);
}

function cb_post($k)
{
    return (isset($_POST[$k]) && is_string($_POST[$k])) ? $_POST[$k] : '';
}

/**
 * Texte nettoyé : caractères de contrôle, espaces, longueur max.
 * Pas de strip_tags : il tronquerait « surface <100 m2 ». L'échappement HTML
 * est fait à l'affichage par cb_h() (emails, pages), le CSV par cb_csv_cell().
 */
function cb_clean($v, $max, $multiline = false)
{
    $v = (string) $v;
    if (!mb_check_encoding($v, 'UTF-8')) {
        $v = mb_convert_encoding($v, 'UTF-8', 'Windows-1252');
    }
    $v = str_replace("\r\n", "\n", $v);
    if ($multiline) {
        $v = preg_replace('/[\x00-\x09\x0B-\x1F\x7F]/u', '', $v);
        $v = preg_replace("/\n{3,}/", "\n\n", (string) $v);
    } else {
        $v = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $v);
        $v = preg_replace('/\s{2,}/u', ' ', (string) $v);
    }
    $v = trim((string) $v);
    return mb_substr($v, 0, $max);
}

/** Valeur de radio contrôlée par liste blanche. */
function cb_pick($k, array $allowed)
{
    $v = trim(cb_post($k));
    return in_array($v, $allowed, true) ? $v : '';
}

function cb_h($s)
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Neutralise les formules de tableur (=, @, +/- non numériques) dans le CSV. */
function cb_csv_cell($v)
{
    $v = str_replace(array("\r", "\n"), ' ', (string) $v);
    if ($v !== '' && (strpbrk($v[0], '=@') !== false || (strpbrk($v[0], '+-') !== false && !preg_match('/^[+-]?\d/', $v)))) {
        $v = "'" . $v;
    }
    return $v;
}

function cb_append_csv($file, array $header, array $row)
{
    $path = cb_private_dir() . '/' . $file;
    $new = !is_file($path) || filesize($path) === 0;
    $fh = @fopen($path, 'a');
    if (!$fh) {
        error_log('contact.php : impossible d\'écrire ' . $path);
        return false;
    }
    flock($fh, LOCK_EX);
    if ($new) {
        fputcsv($fh, $header, ';');
    }
    $ok = fputcsv($fh, array_map('cb_csv_cell', $row), ';') !== false;
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    @chmod($path, 0600);
    return $ok;
}

function cb_log($file, $line)
{
    $path = cb_private_dir() . '/' . $file;
    @file_put_contents($path, date('Y-m-d H:i:s') . ' ' . $line . "\n", FILE_APPEND | LOCK_EX);
    @chmod($path, 0600);
}

function cb_ini_bytes($v)
{
    $v = trim((string) $v);
    if ($v === '') {
        return 0;
    }
    $n = (float) $v;
    switch (strtolower(substr($v, -1))) {
        case 'g':
            $n *= 1024;
            // no break
        case 'm':
            $n *= 1024;
            // no break
        case 'k':
            $n *= 1024;
    }
    return (int) $n;
}

/** Liste (une entrée par ligne, # = commentaire) lue dans le dossier privé, sinon valeurs par défaut. */
function cb_list($file, array $defaults)
{
    $path = cb_private_dir() . '/' . $file;
    if (!is_file($path)) {
        return $defaults;
    }
    $out = array();
    foreach (preg_split('/\R/', (string) @file_get_contents($path)) as $line) {
        $line = trim((string) preg_replace('/#.*/', '', $line));
        if ($line !== '') {
            $out[] = strtolower($line);
        }
    }
    return $out;
}

/** Téléphone français -> +33XXXXXXXXX, ou '' si invalide (même règle que devis.js). */
function cb_phone_e164($raw)
{
    $d = preg_replace('/[\s.\-()]/u', '', (string) $raw);
    if (!preg_match('/^(?:\+33|0033|0)([1-79]\d{8})$/', (string) $d, $m)) {
        return '';
    }
    $nine = $m[1];
    if (preg_match('/(\d)\1{7}/', $nine) || '0' . $nine === '0123456789') {
        return '';
    }
    return '+33' . $nine;
}

function cb_phone_national($e164)
{
    if ($e164 === '') {
        return '';
    }
    return trim(chunk_split('0' . substr($e164, 3), 2, ' '));
}

/** JSON lu / écrit sous verrou dans le dossier privé. $fn reçoit et renvoie le tableau. */
function cb_json_update($rel, $fn)
{
    $path = cb_private_dir() . '/' . $rel;
    $dir = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    $fh = @fopen($path, 'c+');
    if (!$fh) {
        return call_user_func($fn, array());
    }
    flock($fh, LOCK_EX);
    $raw = stream_get_contents($fh);
    $data = json_decode((string) $raw, true);
    if (!is_array($data)) {
        $data = array();
    }
    $data = call_user_func($fn, $data);
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($data));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    @chmod($path, 0600);
    return $data;
}

/** Ménage occasionnel des jetons et compteurs anciens (plus de 2 jours). */
function cb_housekeeping()
{
    if (mt_rand(1, 50) !== 1) {
        return;
    }
    foreach (array('rl', 'tokens') as $sub) {
        $files = glob(cb_private_dir() . '/' . $sub . '/*.json');
        foreach ((is_array($files) ? $files : array()) as $f) {
            if (is_file($f) && filemtime($f) < time() - 172800) {
                @unlink($f);
            }
        }
    }
}

/* =========================================================================
   Pages de réponse
   ========================================================================= */

function cb_page($code, $title, $intro, array $items)
{
    http_response_code($code);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, max-age=0');
    header('X-Robots-Tag: noindex, nofollow');
    $li = '';
    foreach ($items as $it) {
        $li .= '<li>' . cb_h($it) . '</li>';
    }
    echo '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<meta name="robots" content="noindex,nofollow"><title>' . cb_h($title) . ' - Cleanibat</title>'
        . '<link rel="stylesheet" href="/assets/css/style.css">'
        . '<style>body{margin:0;background:#f7f8fa;font-family:Inter,"Segoe UI",sans-serif;color:#1c212b;line-height:1.6}'
        . '.cb-wrap{max-width:640px;margin:0 auto;padding:48px 16px}'
        . '.cb-card{background:#fff;border:1px solid #e2e6ec;border-radius:22px;box-shadow:0 20px 48px rgba(16,29,56,.16);padding:32px}'
        . '.cb-card h1{font-family:Poppins,"Segoe UI",sans-serif;color:#101d38;font-size:26px;line-height:1.2;margin:0 0 12px}'
        . '.cb-card ul{margin:0 0 22px;padding-left:20px;color:#b42318;font-weight:600}.cb-card li{margin-bottom:6px}'
        . '.cb-btn{display:inline-flex;align-items:center;justify-content:center;width:100%;min-height:52px;border:0;border-radius:999px;'
        . 'background:#3f7a1c;color:#fff;font:600 16px Poppins,"Segoe UI",sans-serif;cursor:pointer;margin-bottom:14px}'
        . '.cb-card a{color:#1c3567;font-weight:600}.cb-logo{display:block;margin:0 auto 24px;height:38px;width:auto}</style>'
        . '</head><body><main class="cb-wrap">'
        . '<img class="cb-logo" src="/assets/img/logo/logo-color.webp" alt="Cleanibat" width="144" height="38">'
        . '<div class="cb-card"><h1>' . cb_h($title) . '</h1><p>' . cb_h($intro) . '</p>'
        . ($li !== '' ? '<ul>' . $li . '</ul>' : '')
        . '<button type="button" class="cb-btn" onclick="history.back()">Revenir au formulaire</button>'
        . '<p>Vous préférez nous appeler ? <a href="tel:' . CB_PHONE_INTL . '">' . CB_PHONE_DISPLAY . '</a></p>'
        . '</div></main></body></html>';
    exit;
}

/** Réponse identique à un vrai envoi (les robots ne voient pas la différence). */
function cb_spam($reason, array $f)
{
    cb_append_csv('spam.csv', array('date', 'raison', 'ip_hash', 'nom', 'telephone', 'email', 'extrait'), array(
        date('Y-m-d H:i:s'), $reason, cb_ip_hash(),
        trim((isset($f['prenom']) ? $f['prenom'] : '') . ' ' . (isset($f['nom']) ? $f['nom'] : '')),
        isset($f['telephone_raw']) ? $f['telephone_raw'] : '',
        isset($f['email']) ? $f['email'] : '',
        mb_substr(isset($f['message']) ? $f['message'] : '', 0, 160),
    ));
    cb_housekeeping();
    header('Cache-Control: no-store');
    header('Location: /merci.html?ref=' . date('ymd-His') . '-' . bin2hex(random_bytes(3)), true, 303);
    exit;
}

/* =========================================================================
   Email
   ========================================================================= */

function cb_mime_name($name)
{
    return preg_match('/[^\x20-\x7E]/', $name) ? mb_encode_mimeheader($name, 'UTF-8', 'B', "\r\n") : '"' . addcslashes($name, '"\\') . '"';
}

function cb_mail($to, $subject, $text, $html, array $atts, $fromName, $replyTo)
{
    $c = cb_config();
    $from = filter_var($c['from'], FILTER_VALIDATE_EMAIL) ? $c['from'] : 'no-reply@cleanibat.fr';
    $eol = "\r\n";
    $alt = 'cb-alt-' . bin2hex(random_bytes(8));
    $mix = 'cb-mix-' . bin2hex(random_bytes(8));
    $headers = array(
        'From: ' . cb_mime_name($fromName) . ' <' . $from . '>',
        'Message-ID: <' . date('YmdHis') . '.' . bin2hex(random_bytes(6)) . '@cleanibat.fr>',
        'Date: ' . date('r'),
        'MIME-Version: 1.0',
        'X-Mailer: cleanibat-site',
    );
    if ($replyTo !== '' && filter_var($replyTo, FILTER_VALIDATE_EMAIL)) {
        $headers[] = 'Reply-To: ' . $replyTo;
    }
    $altBody = '--' . $alt . $eol
        . 'Content-Type: text/plain; charset=UTF-8' . $eol
        . 'Content-Transfer-Encoding: base64' . $eol . $eol
        . chunk_split(base64_encode($text), 76, $eol)
        . '--' . $alt . $eol
        . 'Content-Type: text/html; charset=UTF-8' . $eol
        . 'Content-Transfer-Encoding: base64' . $eol . $eol
        . chunk_split(base64_encode($html), 76, $eol)
        . '--' . $alt . '--' . $eol;
    if ($atts) {
        $headers[] = 'Content-Type: multipart/mixed; boundary="' . $mix . '"';
        $body = '--' . $mix . $eol
            . 'Content-Type: multipart/alternative; boundary="' . $alt . '"' . $eol . $eol
            . $altBody;
        foreach ($atts as $a) {
            $name = preg_replace('/[^A-Za-z0-9._-]/', '_', $a['name']);
            $body .= '--' . $mix . $eol
                . 'Content-Type: ' . $a['type'] . '; name="' . $name . '"' . $eol
                . 'Content-Transfer-Encoding: base64' . $eol
                . 'Content-Disposition: attachment; filename="' . $name . '"' . $eol . $eol
                . chunk_split(base64_encode($a['data']), 76, $eol);
        }
        $body .= '--' . $mix . '--' . $eol;
    } else {
        $headers[] = 'Content-Type: multipart/alternative; boundary="' . $alt . '"';
        $body = $altBody;
    }
    $subj = mb_encode_mimeheader($subject, 'UTF-8', 'B', $eol);
    return @mail($to, $subj, $body, implode($eol, $headers), '-f' . $from);
}

/* =========================================================================
   Listes blanches (mêmes valeurs que site/form.py)
   ========================================================================= */

$SERVICE_LABELS = array(
    'toiture' => 'Toiture',
    'toiture-hydrofuge' => 'Traitement hydrofuge',
    'toiture-gouttieres' => 'Gouttières',
    'facade' => 'Façade',
    'terrasse' => 'Terrasse / allée',
    'professionnel' => 'Professionnel',
);
// Valeur envoyée à Make : les 4 valeurs historiques (filtres Make / Odoo inchangés).
$SERVICE_MAKE = array(
    'toiture' => 'toiture', 'toiture-hydrofuge' => 'toiture', 'toiture-gouttieres' => 'toiture',
    'facade' => 'facade', 'terrasse' => 'terrasse', 'professionnel' => 'professionnel',
);
$PILLS = array(
    'couverture' => array('Couverture', array('tuile-terre-cuite' => 'tuile terre cuite', 'tuile-beton' => 'tuile béton',
        'ardoise' => 'ardoise', 'fibrociment' => 'fibrociment', 'bac-acier' => 'bac acier', 'nsp' => 'ne sait pas')),
    'etat' => array('Mousse', array('peu' => 'un peu', 'moyen' => 'bien visible', 'important' => 'toiture très encrassée',
        'nsp' => 'ne sait pas')),
    'finition' => array('Finition', array('incolore' => 'incolore', 'colore' => 'colorée', 'conseil' => 'souhaite un conseil')),
    'revetement' => array('Revêtement', array('enduit' => 'enduit', 'brique' => 'brique', 'pierre' => 'pierre',
        'bardage' => 'bardage', 'autre' => 'autre')),
    'hauteur' => array('Hauteur', array('plain-pied' => 'plain-pied', 'r1' => 'un étage', 'r2' => 'deux étages ou plus')),
    'materiau' => array('Matériau', array('carrelage' => 'carrelage', 'pierre' => 'pierre naturelle', 'beton' => 'béton',
        'paves' => 'pavés', 'bois' => 'bois', 'autre' => 'autre')),
    'avec_toiture' => array('Toiture aussi', array('non' => 'non', 'oui' => 'oui')),
    'type_site' => array('Type', array('copropriete' => 'copropriété', 'commerce' => 'commerce, bureaux',
        'industriel' => 'site industriel, entrepôt', 'collectivite' => 'collectivité', 'autre' => 'autre')),
);
$SURFACES = array('Moins de 80 m²', '80 à 120 m²', '120 à 180 m²', 'Plus de 180 m²', 'Je ne sais pas',
    'Moins de 30 m²', '30 à 60 m²', '60 à 100 m²', 'Plus de 100 m²');
$DELAIS = array('des-que-possible' => 'Dès que possible', '1-3-mois' => 'Dans 1 à 3 mois',
    '3-6-mois' => 'Dans 3 à 6 mois', 'autre' => 'Autre / se renseigne');
$TRACKING = array('utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'gclid', 'fbclid',
    'first_utm_source', 'first_landing_page', 'landing_page', 'referrer', 'page_url', 'cta_source');
$DISPOSABLE_DEFAULT = array('prodmail.online', 'probox.my.id', 'yopmail.com', 'yopmail.fr', 'mailinator.com',
    'guerrillamail.com', 'sharklasers.com', '10minutemail.com', 'temp-mail.org', 'tempmail.com', 'trashmail.com',
    'maildrop.cc', 'getnada.com', 'dispostable.com', 'fakeinbox.com', 'mohmal.com', 'emailondeck.com');

/* =========================================================================
   0. Méthode, jeton, taille
   ========================================================================= */

$method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper((string) $_SERVER['REQUEST_METHOD']) : 'GET';

if ($method === 'GET' && isset($_GET['jeton'])) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow');
    $t = (string) time();
    echo json_encode(array('t' => (int) $t, 'h' => cb_sig($t), 'b' => cb_bind($t)));
    exit;
}

if ($method !== 'POST') {
    header('Allow: POST');
    header('X-Robots-Tag: noindex, nofollow');
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Méthode non autorisée.\n";
    exit;
}

$contentLength = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
if (empty($_POST) && empty($_FILES) && $contentLength > 0 && $contentLength > cb_ini_bytes(ini_get('post_max_size'))) {
    cb_page(413, 'Vos photos sont trop lourdes',
        'Votre demande n\'a pas pu être envoyée : les photos dépassent la taille autorisée. Renvoyez-la avec moins de photos (ou sans photo) ou appelez-nous au ' . CB_PHONE_DISPLAY . '.',
        array());
}

$CFG = cb_config();
$isTest = (isset($_GET['test']) && in_array($_GET['test'], array('1', 'make'), true)) || cb_post('_test') === '1';
$testMake = isset($_GET['test']) && $_GET['test'] === 'make';

/* =========================================================================
   1. Nettoyage
   ========================================================================= */

$raw = array();
foreach (array('prenom', 'nom', 'ville', 'societe', 'message') as $k) {
    $raw[$k] = cb_post($k);
}
$F = array(
    'prenom' => cb_clean($raw['prenom'], 60),
    'nom' => cb_clean($raw['nom'], 60),
    'telephone_raw' => cb_clean(cb_post('telephone'), 30),
    'email' => strtolower(cb_clean(cb_post('email'), 100)),
    'code_postal' => cb_clean(cb_post('code_postal'), 10),
    'ville' => cb_clean($raw['ville'], 80),
    'societe' => cb_clean($raw['societe'], 100),
    'message' => cb_clean($raw['message'], 1500, true),
    'service' => cb_pick('service', array_keys($SERVICE_LABELS)),
    'surface' => cb_pick('surface', $SURFACES),
    'delai' => cb_pick('delai', array_keys($DELAIS)),
    'consent' => cb_post('consent') === 'on' ? 'on' : '',
    'form_location' => (string) preg_replace('/[^a-z0-9-]/', '', strtolower(cb_clean(cb_post('form_location'), 60))),
    'website' => cb_post('website'),
);
foreach ($PILLS as $k => $def) {
    $F[$k] = cb_pick($k, array_keys($def[1]));
}
$A = array();
foreach ($TRACKING as $k) {
    $A[$k] = cb_clean(cb_post($k), 300);
}
foreach (array('gbraid', 'wbraid', 'msclkid') as $k) {
    $A[$k] = cb_clean(cb_post($k), 300);
}

/* =========================================================================
   2. Robots (silencieux) et suspects
   ========================================================================= */

if (trim($F['website']) !== '') {
    cb_spam('champ_piege', $F);
}

$suspect = array();
$t = trim(cb_post('_t'));
$h = trim(cb_post('_h'));
$b = trim(cb_post('_b'));
$tokenKey = '';
if ($t === '' && $h === '') {
    $suspect[] = 'sans jeton (JavaScript absent)';
} else {
    if (!preg_match('/^\d{1,12}$/', $t) || !hash_equals(cb_sig($t), $h)) {
        cb_spam('jeton_faux', $F);
    }
    $age = time() - (int) $t;
    if ($age < (int) $CFG['min_seconds']) {
        cb_spam('trop_rapide', $F);
    }
    if ($age > (int) $CFG['max_seconds']) {
        cb_spam('jeton_expire', $F);
    }
    $tokenKey = sha1($h);
    $tokFile = cb_private_dir() . '/tokens/' . $tokenKey . '.json';
    if (is_file($tokFile)) {
        $tk = json_decode((string) @file_get_contents($tokFile), true);
        if (is_array($tk) && isset($tk['n']) && (int) $tk['n'] >= (int) $CFG['token_max_uses']) {
            cb_spam('jeton_rejoue', $F);
        }
    }
    if ($b === '' || !hash_equals(cb_bind($t), $b)) {
        $suspect[] = 'jeton obtenu depuis un autre navigateur';
    }
}

$email = $F['email'];
$emailDomain = ($email !== '' && strpos($email, '@') !== false) ? substr((string) strrchr($email, '@'), 1) : '';
if ($emailDomain !== '') {
    $disposable = cb_list('disposable.txt', $DISPOSABLE_DEFAULT);
    if (in_array($emailDomain, $disposable, true) || preg_match('/\.my\.id$/', $emailDomain)) {
        cb_spam('email_jetable', $F);
    }
}

$phoneE164 = cb_phone_e164($F['telephone_raw']);
if ($F['telephone_raw'] !== '') {
    $digits = preg_replace('/\D/', '', $F['telephone_raw']);
    foreach (cb_list('blocklist_tel.txt', array()) as $entry) {
        $entryDigits = preg_replace('/\D/', '', $entry);
        if ($entryDigits === '') {
            continue;
        }
        $entryE164 = cb_phone_e164($entry);
        if (($entryE164 !== '' && $entryE164 === $phoneE164) || $entryDigits === $digits) {
            cb_spam('tel_liste_noire', $F);
        }
    }
}

// Liens et alphabets étrangers : jamais rejetés en silence (un vrai client peut écrire une adresse).
foreach ($raw as $k => $v) {
    if (preg_match('~(https?://|www\.|<a\s|\[url)~i', $v)) {
        $suspect[] = 'lien dans le champ ' . $k;
        break;
    }
}
foreach ($raw as $k => $v) {
    if (@preg_match('/[\p{Cyrillic}\p{Han}\p{Arabic}]/u', $v)) {
        $suspect[] = 'alphabet cyrillique, chinois ou arabe dans le champ ' . $k;
        break;
    }
}

/* =========================================================================
   3. Validation humaine
   ========================================================================= */

$errors = array();
if ($F['service'] === '') {
    $errors[] = 'Choisissez le type de travaux pour continuer.';
}
if (!preg_match('/^\d{5}$/', $F['code_postal'])) {
    $errors[] = 'Indiquez un code postal à 5 chiffres (ex : 62300).';
}
if ($F['ville'] === '') {
    $errors[] = 'Indiquez votre commune.';
}
if (preg_match_all('/\p{L}/u', $F['prenom']) < 2) {
    $errors[] = 'Indiquez votre prénom.';
}
if (preg_match_all('/\p{L}/u', $F['nom']) < 2) {
    $errors[] = 'Indiquez votre nom.';
}
if ($F['telephone_raw'] === '') {
    $errors[] = 'Indiquez votre numéro pour que nous puissions vous rappeler.';
} elseif ($phoneE164 === '') {
    $errors[] = 'Ce numéro ne semble pas valide. Exemple : 06 12 34 56 78.';
}
$emailOk = false;
if ($email !== '') {
    $emailOk = (bool) filter_var($email, FILTER_VALIDATE_EMAIL);
    if ($emailOk && !empty($CFG['check_dns']) && function_exists('checkdnsrr')) {
        $emailOk = checkdnsrr($emailDomain . '.', 'MX') || checkdnsrr($emailDomain . '.', 'A') || checkdnsrr($emailDomain . '.', 'AAAA');
    }
    if (!$emailOk) {
        $errors[] = 'Cette adresse email ne semble pas valide (vous pouvez aussi laisser ce champ vide).';
    }
}
if ($F['consent'] !== 'on') {
    $errors[] = 'Cochez la case pour que nous puissions vous recontacter.';
}
if ($errors) {
    cb_page(422, 'Il manque quelques informations',
        'Votre demande n\'est pas encore partie. Revenez au formulaire (vos réponses sont conservées) pour corriger :',
        $errors);
}

// Limite par IP : seulement les envois valides (un vrai client qui corrige ses erreurs n'est pas bloqué).
$now = time();
$rl = cb_json_update('rl/' . cb_ip_hash() . '.json', function ($d) use ($now) {
    $keep = array();
    foreach ($d as $ts) {
        if (is_int($ts) && $ts > $now - 86400) {
            $keep[] = $ts;
        }
    }
    $keep[] = $now;
    return $keep;
});
$in10 = 0;
foreach ($rl as $ts) {
    if ($ts > $now - 600) {
        $in10++;
    }
}
if ($in10 > (int) $CFG['rate_10min'] || count($rl) > (int) $CFG['rate_24h']) {
    if ($isTest) {
        // Mode test (recette) : même limite (?test=1 est public), mais réponse explicite.
        cb_append_csv('spam.csv', array('date', 'raison', 'ip_hash', 'nom', 'telephone', 'email', 'extrait'),
            array(date('Y-m-d H:i:s'), 'limite_ip', cb_ip_hash(), '', '', '', '[TEST]'));
        cb_page(429, '[TEST] Limite d\'envois atteinte',
            'Mode test : plus de ' . (int) $CFG['rate_10min'] . ' envois en 10 minutes (ou ' . (int) $CFG['rate_24h']
            . ' en 24 h) depuis cette connexion. Rien n\'est parti. Attendez 10 minutes avant de recommencer.',
            array());
    }
    cb_spam('limite_ip', $F);
}

/* =========================================================================
   4. Photos
   ========================================================================= */

$leadId = date('ymd-His') . '-' . bin2hex(random_bytes(3));
$photoNotes = array();
$photoFiles = array();
$MIME_EXT = array('image/jpeg' => 'jpg', 'image/pjpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp',
    'image/heic' => 'heic', 'image/heif' => 'heif', 'image/heic-sequence' => 'heic', 'image/heif-sequence' => 'heif');
if (isset($_FILES['photos']) && is_array($_FILES['photos']['name'])) {
    $P = $_FILES['photos'];
    $total = 0;
    $count = count($P['name']);
    $finfo = function_exists('finfo_open') ? finfo_open(FILEINFO_MIME_TYPE) : false;
    for ($i = 0; $i < $count; $i++) {
        $err = (int) $P['error'][$i];
        if ($err === UPLOAD_ERR_NO_FILE) {
            continue;
        }
        if (count($photoFiles) >= 3) {
            $photoNotes[] = 'photo ignorée (3 photos maximum)';
            continue;
        }
        if ($err === UPLOAD_ERR_INI_SIZE || $err === UPLOAD_ERR_FORM_SIZE || (int) $P['size'][$i] > 8 * 1024 * 1024) {
            $photoNotes[] = 'photo trop lourde ignorée (8 Mo max)';
            continue;
        }
        if ($err !== UPLOAD_ERR_OK || !is_uploaded_file($P['tmp_name'][$i])) {
            $photoNotes[] = 'photo non reçue (erreur ' . $err . ')';
            continue;
        }
        if ($total + (int) $P['size'][$i] > 20 * 1024 * 1024) {
            $photoNotes[] = 'photo ignorée (20 Mo au total)';
            continue;
        }
        $mime = $finfo ? (string) finfo_file($finfo, $P['tmp_name'][$i]) : '';
        $origExt = strtolower((string) pathinfo((string) $P['name'][$i], PATHINFO_EXTENSION));
        if (!isset($MIME_EXT[$mime]) && in_array($origExt, array('heic', 'heif'), true)
            && in_array($mime, array('application/octet-stream', ''), true)) {
            $mime = 'image/' . $origExt; // anciennes versions de libmagic : HEIC non reconnu
        }
        if (!isset($MIME_EXT[$mime])) {
            $photoNotes[] = 'fichier refusé (format ' . ($mime !== '' ? $mime : 'inconnu') . ')';
            continue;
        }
        $total += (int) $P['size'][$i];
        $photoFiles[] = array('tmp' => $P['tmp_name'][$i], 'type' => $mime, 'ext' => $MIME_EXT[$mime], 'size' => (int) $P['size'][$i]);
    }
    if ($finfo) {
        finfo_close($finfo);
    }
}

/* =========================================================================
   5. Statut, origine, synthèse
   ========================================================================= */

$dupWindow = (int) $CFG['dup_minutes'] * 60;
$isDup = false;
if (!$isTest) {
    cb_json_update('recent.json', function ($d) use ($phoneE164, $now, $dupWindow, &$isDup) {
        $keep = array();
        foreach ($d as $tel => $ts) {
            if (is_int($ts) && $ts > $now - $dupWindow) {
                $keep[$tel] = $ts;
            }
        }
        if (isset($keep[$phoneE164])) {
            $isDup = true;
        }
        $keep[$phoneE164] = $now;
        return $keep;
    });
}
if ($isTest) {
    $status = 'test';
} elseif ($suspect) {
    $status = 'suspect';
} elseif ($isDup) {
    $status = 'doublon';
} else {
    $status = 'ok';
}

// Jeton : un usage de plus.
if ($tokenKey !== '') {
    cb_json_update('tokens/' . $tokenKey . '.json', function ($d) {
        $d['n'] = (isset($d['n']) ? (int) $d['n'] : 0) + 1;
        return $d;
    });
}

// Photos : déplacées dans le dossier privé (jamais dans le docroot), nom aléatoire.
$photoSaved = array();
if ($photoFiles) {
    $pdir = cb_private_dir() . '/photos/' . date('Y-m');
    if (!is_dir($pdir)) {
        @mkdir($pdir, 0700, true);
    }
    foreach ($photoFiles as $n => $pf) {
        $name = $leadId . '-' . ($n + 1) . '.' . $pf['ext'];
        $dest = $pdir . '/' . $name;
        if (@move_uploaded_file($pf['tmp'], $dest)) {
            @chmod($dest, 0600);
            $photoSaved[] = array('path' => $dest, 'name' => $name, 'type' => $pf['type'], 'size' => $pf['size']);
        } else {
            $photoNotes[] = 'photo non enregistrée sur le serveur';
        }
    }
}
$nbPhotos = count($photoSaved);

// Origine (même logique que le site Rénovation de vos rêves).
$us = strtolower($A['utm_source']);
$um = strtolower($A['utm_medium']);
$refHost = ($A['referrer'] !== '' && $A['referrer'] !== 'direct') ? strtolower((string) parse_url($A['referrer'], PHP_URL_HOST)) : '';
$moteur = '';
foreach (array('google', 'bing', 'qwant', 'duckduckgo', 'ecosia', 'yahoo', 'yandex', 'startpage', 'lilo', 'brave', 'baidu', 'ask') as $m) {
    if ($refHost !== '' && preg_match('/(^|\.)' . $m . '\./', $refHost)) {
        $moteur = $m;
        break;
    }
}
$isDirectUtm = ($us === '' || $us === 'direct');
if ($A['gclid'] !== '' || $A['gbraid'] !== '' || $A['wbraid'] !== '' || ($us === 'google' && in_array($um, array('cpc', 'ppc', 'paid', 'paid_search', 'sea'), true))) {
    $origine = 'Google Ads';
    $origineDetail = trim(($A['utm_campaign'] !== '' ? $A['utm_campaign'] . ' · ' : '') . ($A['gclid'] !== '' ? 'gclid' : ($A['gbraid'] !== '' ? 'gbraid' : ($A['wbraid'] !== '' ? 'wbraid' : 'utm'))));
} elseif ($A['fbclid'] !== '' || in_array($us, array('facebook', 'fb', 'instagram', 'ig', 'meta'), true)) {
    $origine = 'Meta Ads';
    $origineDetail = $A['utm_campaign'] !== '' ? $A['utm_campaign'] : 'fbclid';
} elseif ($moteur !== '' && $isDirectUtm && $A['msclkid'] === '') {
    $origine = 'SEO';
    $origineDetail = 'recherche ' . $refHost;
} elseif ($A['msclkid'] !== '' || !$isDirectUtm) {
    $origine = 'Autre';
    $origineDetail = $A['msclkid'] !== '' ? 'Microsoft Ads' : 'utm ' . $A['utm_source'] . '/' . $A['utm_medium'];
} elseif ($refHost !== '') {
    $origine = 'Autre';
    $origineDetail = 'lien depuis ' . $refHost;
} else {
    $origine = 'Direct';
    $origineDetail = 'accès direct';
}

$serviceLabel = $SERVICE_LABELS[$F['service']];
$precisions = array();
foreach ($PILLS as $k => $def) {
    if ($F[$k] !== '') {
        $precisions[] = $def[0] . ' : ' . $def[1][$F[$k]];
    }
}
if ($F['service'] === 'professionnel' && $F['societe'] !== '') {
    array_unshift($precisions, 'Société : ' . $F['societe']);
}
$synthParts = $precisions;
if ($nbPhotos > 0) {
    $synthParts[] = 'Photos : ' . $nbPhotos . ' (envoyées par email)';
}
$synthParts[] = 'Réf. ' . $leadId;
$synth = '[' . $serviceLabel . '] ' . implode(' · ', $synthParts) . ' |'
    . ($F['message'] !== '' ? ' ' . str_replace(array("\r", "\n"), ' ', $F['message']) : '');
$phoneNat = cb_phone_national($phoneE164);
$delaiLabel = $F['delai'] !== '' ? $DELAIS[$F['delai']] : 'non précisé';

/* =========================================================================
   6. leads.csv AVANT tout envoi
   ========================================================================= */

$trackValues = array();
foreach ($TRACKING as $k) {
    $trackValues[] = $A[$k];
}
cb_append_csv('leads.csv',
    array_merge(array('date', 'lead_id', 'statut', 'motif', 'service', 'service_detail', 'precisions', 'surface', 'delai',
        'code_postal', 'ville', 'prenom', 'nom', 'telephone', 'email', 'societe', 'message', 'nb_photos', 'origine',
        'origine_detail', 'form_location'), $TRACKING, array('ip_hash')),
    array_merge(array(date('Y-m-d H:i:s'), $leadId, $status, implode(' ; ', $suspect), $SERVICE_MAKE[$F['service']],
        $F['service'], implode(' · ', $precisions), $F['surface'], $F['delai'], $F['code_postal'], $F['ville'],
        $F['prenom'], $F['nom'], $phoneE164, $email, $F['societe'], $F['message'], $nbPhotos, $origine, $origineDetail,
        $F['form_location']), $trackValues, array(cb_ip_hash())));

/* =========================================================================
   7. Email au gérant
   ========================================================================= */

$prefix = '';
if ($status === 'test') {
    $prefix = '[TEST] ';
} elseif ($status === 'suspect') {
    $prefix = '[À vérifier] ';
} elseif ($status === 'doublon') {
    $prefix = '[Doublon] ';
}
$subject = $prefix . 'Nouvelle demande de devis - ' . $serviceLabel . ' - ' . $F['ville'] . ' (' . $F['code_postal'] . ') - '
    . $F['prenom'] . ' ' . $F['nom'];

$mapsUrl = 'https://www.google.com/maps/search/?api=1&query=' . rawurlencode($F['ville'] . ' ' . $F['code_postal'] . ' France');
$rows = array(
    array('Besoin', cb_h($serviceLabel)),
    array('Précisions', $precisions ? cb_h(implode(' · ', $precisions)) : '-'),
    array('Surface', $F['surface'] !== '' ? cb_h($F['surface']) : '-'),
    array('Délai', cb_h($delaiLabel)),
    array('Commune', '<a href="' . cb_h($mapsUrl) . '">' . cb_h($F['ville'] . ' (' . $F['code_postal'] . ')') . '</a>'),
    array('Coordonnées', cb_h($F['prenom'] . ' ' . $F['nom']) . '<br><a href="tel:' . cb_h($phoneE164) . '">' . cb_h($phoneNat) . '</a>'
        . ($email !== '' ? '<br><a href="mailto:' . cb_h($email) . '">' . cb_h($email) . '</a>' : '<br>pas d\'email')),
    array('Message', $F['message'] !== '' ? nl2br(cb_h($F['message'])) : '-'),
    array('Photos', $nbPhotos . ' jointe(s)' . ($photoNotes ? ' · ' . cb_h(implode(' ; ', $photoNotes)) : '')),
    array('Origine', cb_h($origine . ' · ' . $origineDetail)
        . '<br>Campagne : ' . cb_h($A['utm_campaign'] !== '' ? $A['utm_campaign'] : '-')
        . '<br>Page d\'arrivée : ' . cb_h($A['landing_page'] !== '' ? $A['landing_page'] : '-')
        . '<br>Formulaire : ' . cb_h($F['form_location']) . ' · CTA : ' . cb_h($A['cta_source'] !== '' ? $A['cta_source'] : '-')),
    array('Référence', cb_h($leadId)),
);
if ($suspect) {
    array_unshift($rows, array('À vérifier', cb_h(implode(' ; ', $suspect)) . '<br>Non envoyé à Make : à saisir dans Odoo si la demande est réelle.'));
}
if ($status === 'doublon') {
    array_unshift($rows, array('Doublon', 'Même numéro reçu il y a moins de ' . (int) $CFG['dup_minutes'] . ' min : non renvoyé à Make.'));
}
$table = '';
foreach ($rows as $r) {
    $table .= '<tr><th style="text-align:left;vertical-align:top;padding:10px 12px;border-bottom:1px solid #e2e6ec;color:#454c58;'
        . 'font:600 13px Arial,sans-serif;width:120px">' . $r[0] . '</th><td style="padding:10px 12px;border-bottom:1px solid #e2e6ec;'
        . 'font:15px Arial,sans-serif;color:#1c212b">' . $r[1] . '</td></tr>';
}
$civ = 'M./Mme ' . ($F['nom'] !== '' ? $F['nom'] : $F['prenom']);
$html = '<!DOCTYPE html><html lang="fr"><body style="margin:0;padding:16px;background:#f7f8fa">'
    . '<div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #e2e6ec;border-radius:14px;padding:20px">'
    . '<p style="margin:0 0 16px"><a href="tel:' . cb_h($phoneE164) . '" style="display:block;text-align:center;background:#3f7a1c;color:#fff;'
    . 'text-decoration:none;font:700 18px Arial,sans-serif;padding:16px;border-radius:999px">Appeler ' . cb_h($civ) . ' : ' . cb_h($phoneNat) . '</a></p>'
    . '<table style="width:100%;border-collapse:collapse">' . $table . '</table>'
    . '<p style="font:12px Arial,sans-serif;color:#6b7280;margin:16px 0 0">Envoyé par le formulaire de www.cleanibat.fr · statut ' . cb_h($status) . '</p>'
    . '</div></body></html>';
$text = 'Appeler ' . $civ . ' : ' . $phoneNat . "\n\n"
    . ($suspect ? 'À VÉRIFIER : ' . implode(' ; ', $suspect) . "\n(non envoyé à Make : à saisir dans Odoo si la demande est réelle)\n\n" : '')
    . ($status === 'doublon' ? 'DOUBLON : même numéro reçu il y a moins de ' . (int) $CFG['dup_minutes'] . " min (non renvoyé à Make)\n\n" : '')
    . 'Besoin      : ' . $serviceLabel . "\n"
    . 'Précisions  : ' . ($precisions ? implode(' · ', $precisions) : '-') . "\n"
    . 'Surface     : ' . ($F['surface'] !== '' ? $F['surface'] : '-') . "\n"
    . 'Délai       : ' . $delaiLabel . "\n"
    . 'Commune     : ' . $F['ville'] . ' (' . $F['code_postal'] . ') ' . $mapsUrl . "\n"
    . 'Coordonnées : ' . $F['prenom'] . ' ' . $F['nom'] . ' · ' . $phoneNat . ($email !== '' ? ' · ' . $email : '') . "\n"
    . 'Message     : ' . ($F['message'] !== '' ? $F['message'] : '-') . "\n"
    . 'Photos      : ' . $nbPhotos . ($photoNotes ? ' · ' . implode(' ; ', $photoNotes) : '') . "\n"
    . 'Origine     : ' . $origine . ' · ' . $origineDetail . "\n"
    . 'Campagne    : ' . ($A['utm_campaign'] !== '' ? $A['utm_campaign'] : '-') . "\n"
    . 'Arrivée     : ' . ($A['landing_page'] !== '' ? $A['landing_page'] : '-') . "\n"
    . 'Formulaire  : ' . $F['form_location'] . ' · CTA : ' . ($A['cta_source'] !== '' ? $A['cta_source'] : '-') . "\n"
    . 'Référence   : ' . $leadId . "\n";

// Pièces jointes : 18 Mo au plus (limite des messageries), le reste reste sur le serveur.
$atts = array();
$attBytes = 0;
foreach ($photoSaved as $ps) {
    if ($attBytes + $ps['size'] > 18 * 1024 * 1024) {
        continue;
    }
    $data = @file_get_contents($ps['path']);
    if ($data !== false) {
        $atts[] = array('name' => $ps['name'], 'type' => $ps['type'], 'data' => $data);
        $attBytes += strlen($data);
    }
}
$mailOk = cb_mail((string) $CFG['dest'], $subject, $text, $html, $atts, (string) $CFG['from_name'], $emailOk ? $email : '');
if (!$mailOk) {
    cb_log('make.log', $leadId . ' mail_gerant=echec');
}

/* =========================================================================
   8. Redirection vers la page merci, réponse terminée pour le navigateur
   ========================================================================= */

ignore_user_abort(true);
header('Cache-Control: no-store');
header('Location: /merci.html?ref=' . rawurlencode($leadId), true, 303);
header('Content-Length: 0');
header('Connection: close');
if (function_exists('litespeed_finish_request')) {
    litespeed_finish_request();
} elseif (function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
} else {
    while (ob_get_level() > 0) {
        @ob_end_flush();
    }
    @flush();
}

/* =========================================================================
   9. Accusé de réception, Make
   ========================================================================= */

if (!empty($CFG['ack_email']) && $emailOk && ($status === 'ok' || $status === 'test')) {
    $ackText = "Bonjour,\n\n"
        . 'Nous avons bien reçu votre demande de devis (' . $serviceLabel . ', ' . $F['ville'] . '). '
        . 'Nous vous rappelons sous 24h depuis le ' . CB_PHONE_DISPLAY . " : pensez à décrocher.\n\n"
        . "Pour ajouter des photos ou une précision, il suffit de répondre à cet email.\n\n"
        . 'Référence de votre demande : ' . $leadId . "\n\n"
        . "Aymeric - Cleanibat\n" . CB_PHONE_DISPLAY . "\nwww.cleanibat.fr\n";
    $ackHtml = '<!DOCTYPE html><html lang="fr"><body style="margin:0;padding:16px;background:#f7f8fa">'
        . '<div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e2e6ec;border-radius:14px;padding:24px;'
        . 'font:15px/1.6 Arial,sans-serif;color:#1c212b">'
        . '<p>Bonjour,</p>'
        . '<p>Nous avons bien reçu votre demande de devis (' . cb_h($serviceLabel . ', ' . $F['ville']) . '). '
        . 'Nous vous rappelons sous 24h depuis le <a href="tel:' . CB_PHONE_INTL . '" style="color:#1c3567;font-weight:bold">'
        . CB_PHONE_DISPLAY . '</a> : pensez à décrocher.</p>'
        . '<p>Pour ajouter des photos ou une précision, il suffit de répondre à cet email.</p>'
        . '<p style="color:#6b7280;font-size:13px">Référence de votre demande : ' . cb_h($leadId) . '</p>'
        . '<p>Aymeric - Cleanibat<br>' . CB_PHONE_DISPLAY . '<br><a href="' . CB_SITE . '" style="color:#1c3567">www.cleanibat.fr</a></p>'
        . '</div></body></html>';
    $ackOk = cb_mail($email, ($status === 'test' ? '[TEST] ' : '') . 'Votre demande de devis Cleanibat est bien reçue',
        $ackText, $ackHtml, array(), (string) $CFG['ack_from_name'], (string) $CFG['ack_reply_to']);
    if (!$ackOk) {
        cb_log('make.log', $leadId . ' accuse_reception=echec');
    }
}

if ($status === 'ok' || ($status === 'test' && $testMake)) {
    $makeUrl = trim((string) $CFG['make_url']);
    $phoneForMake = $CFG['phone_format'] === 'e164' ? $phoneE164 : $phoneNat;
    // Les 23 clés historiques (mêmes noms qu'avant), puis 4 clés en plus (ignorées par Make si non utilisées).
    $payload = array(
        'nom' => $F['nom'],
        'prenom' => $F['prenom'],
        'email' => $emailOk ? $email : '',
        'telephone' => $phoneForMake,
        'service' => $SERVICE_MAKE[$F['service']],
        'delai' => $F['delai'],
        'ville' => $F['ville'],
        'surface' => $F['surface'],
        'message' => $synth,
        'consent' => 'on',
    );
    foreach ($TRACKING as $k) {
        $payload[$k] = $A[$k];
    }
    $payload['service_detail'] = $F['service'];
    $payload['code_postal'] = $F['code_postal'];
    $payload['photos_count'] = (string) $nbPhotos;
    $payload['lead_id'] = $leadId;
    $payload = array_map('strval', $payload);
    $json = json_encode($payload, JSON_UNESCAPED_UNICODE);

    $code = 0;
    $err = '';
    if ($makeUrl === '') {
        $err = 'make_url absente de config.json';
    } elseif (function_exists('curl_init')) {
        $ch = curl_init($makeUrl);
        curl_setopt_array($ch, array(
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_HTTPHEADER => array('Content-Type: application/json; charset=utf-8'),
            CURLOPT_POSTFIELDS => $json,
        ));
        curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
    } else {
        $ctx = stream_context_create(array('http' => array(
            'method' => 'POST',
            'header' => "Content-Type: application/json; charset=utf-8\r\n",
            'content' => $json,
            'timeout' => 5,
            'ignore_errors' => true,
        )));
        @file_get_contents($makeUrl, false, $ctx);
        if (isset($http_response_header[0]) && preg_match('/\s(\d{3})(\s|$)/', $http_response_header[0], $mm)) {
            $code = (int) $mm[1];
        }
    }
    cb_log('make.log', $leadId . ' statut=' . $status . ' http=' . $code . ($err !== '' ? ' erreur=' . $err : ''));
    if ($makeUrl !== '' && ($code < 200 || $code >= 300)) {
        cb_mail((string) $CFG['dest'], 'Make KO pour ' . $leadId . ' : lead à saisir dans Odoo',
            'Make KO pour ' . $leadId . " : lead à saisir dans Odoo.\n\nCode HTTP : " . $code . ($err !== '' ? "\nErreur : " . $err : '')
            . "\n\n" . $text,
            '<p>Make KO pour <b>' . cb_h($leadId) . '</b> : lead à saisir dans Odoo.</p><p>Code HTTP : ' . $code
            . ($err !== '' ? '<br>Erreur : ' . cb_h($err) : '') . '</p><pre style="font:13px monospace">' . cb_h($text) . '</pre>',
            array(), (string) $CFG['from_name'], '');
    }
}

cb_housekeeping();
exit;
