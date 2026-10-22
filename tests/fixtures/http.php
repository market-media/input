<?php

declare(strict_types=1);

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use MarketMedia\Input\Input;

$input = new Input(maxBodyBytes: 256, maxDepth: 4, maxFields: 12);
// A dependência pode configurar UTF-8 no autoload; force outro charset depois.
ini_set('default_charset', 'ISO-8859-1');
$includeFiles = ($_SERVER['HTTP_X_TEST_INCLUDE_FILES'] ?? '') === '1';
header('Content-Type: application/json');

try {
    echo json_encode([
    'get' => $input->get(),
    'post' => $input->post(includeFiles: $includeFiles),
    'put' => $input->put(includeFiles: $includeFiles),
    'delete' => $input->delete(),
    'getValue' => $input->getValue('value'),
    'postValue' => $input->postValue('value'),
    'requestValue' => $input->requestValue('value'),
    'missingValue' => $input->getValue('missing'),
    ], JSON_THROW_ON_ERROR);
} catch (LengthException) {
    http_response_code(413);
    echo json_encode(['error' => 'input_limit']);
} catch (UnexpectedValueException) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid_input']);
}
