<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use MarketMedia\Input\Input;

$checks = 0;
$check = static function (bool $condition, string $message) use (&$checks): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
    ++$checks;
};

unset($_SERVER['REQUEST_METHOD']);
$input = new Input();
foreach (['get', 'post', 'put', 'delete'] as $method) {
    $check($input->$method() === null, "Método ausente: $method");
}
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = ['name' => 'Ana', 'nested' => ['attack' => '<script>alert(1)</script>']];
$_FILES = ['document' => ['name' => '<img src=x onerror=alert(1)>', 'tmp_name' => '/private/tmp/upload', 'error' => UPLOAD_ERR_OK]];
$data = $input->post();
$check($data['name'] === 'Ana', 'Preservar texto simples');
$check(!str_contains($data['nested']['attack'], '<script>'), 'Sanitizar array aninhado');
$check(!array_key_exists('_files', $data), 'Não expor metadados de upload por padrão');
$check($input->post(includeFiles: true)['_files'] === $_FILES, 'Uploads somente por opção explícita');
$_SERVER['REQUEST_METHOD'] = 'PUT';
$check($input->put() === $data, 'PUT com formulário e arquivos');
$check($input->put(includeFiles: true)['_files'] === $_FILES, 'PUT com uploads explícitos');
$_REQUEST = ['value' => 'cookie-pollution'];
$check($input->requestValue('value') === null, 'Não confiar em $_REQUEST');
$check($input->requestValue('missing') === null, 'Chave ausente');
$_SERVER['HTTP_TEST'] = '<test>';
$check($input->serverValue('HTTP_TEST') === null, 'SERVER usa entrada original do PHP');

$throws = static function (string $class, callable $action, string $message) use ($check): void {
    try {
        $action();
    } catch (Throwable $exception) {
        $check($exception instanceof $class, $message . ': ' . $exception::class);
        return;
    }
    $check(false, $message);
};
foreach ([['maxBodyBytes' => 0], ['maxBodyBytes' => PHP_INT_MAX], ['maxDepth' => 0], ['maxDepth' => 513], ['maxFields' => 0]] as $limits) {
    $throws(InvalidArgumentException::class, static fn () => new Input(...$limits), 'Limites inválidos');
}
$_SERVER['REQUEST_METHOD'] = 'GET';
foreach ([['_files' => ['fake']], ['_files' => null]] as $spoof) {
    $_GET = $spoof;
    $throws(UnexpectedValueException::class, static fn () => $input->get(), 'Bloquear _files falsificado');
}
foreach ([["bad\0key" => 'value'], ["\xFF" => 'value'], ['value' => "\xFF"], ['value' => new stdClass()]] as $invalid) {
    $_GET = $invalid;
    $throws(UnexpectedValueException::class, static fn () => $input->get(), 'Rejeitar chave, UTF-8 ou tipo inválido');
}
$_GET = ['a' => ['b' => ['c' => 'value']]];
$throws(LengthException::class, static fn () => (new Input(maxDepth: 2))->get(), 'Limitar profundidade antes da sanitização');
$_GET = ['a' => 1, 'b' => 2, 'c' => 3];
$throws(LengthException::class, static fn () => (new Input(maxFields: 2))->get(), 'Limitar quantidade de campos');
$_GET = ['a' => str_repeat('x', 32)];
$throws(LengthException::class, static fn () => (new Input(maxBodyBytes: 32))->get(), 'Contabilizar chaves no limite de bytes');
$_GET = ['a' => str_repeat('x', 31)];
$check((new Input(maxBodyBytes: 32))->get() === $_GET, 'Aceitar limite exato de bytes');
$_GET = ['n' => 42, 'b' => false, 'empty' => null];
$check($input->get() === $_GET, 'Preservar tipos escalares');
$_POST = ['_files' => ['fake']];
foreach (['POST' => 'post', 'PUT' => 'put'] as $method => $name) {
    $_SERVER['REQUEST_METHOD'] = $method;
    $throws(UnexpectedValueException::class, static fn () => $input->$name(), 'Bloquear _files em formulário');
}
$_POST = [];
$_SERVER['REQUEST_METHOD'] = 'POST';
$check($input->post() === [], 'Upload sem campos não é JSON');

// Porta temporária para testar php://input e filter_input com requisições reais.
$socket = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
if ($socket === false) {
    throw new RuntimeException($errorMessage, $errorCode);
}
$address = stream_socket_get_name($socket, false);
fclose($socket);
$log = tempnam(sys_get_temp_dir(), 'input-tests-');
$process = proc_open(
    [PHP_BINARY, '-d', 'request_order=GPC', '-d', 'default_charset=ISO-8859-1', '-S', $address, __DIR__ . '/fixtures/http.php'],
    [0 => ['pipe', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']],
    $pipes,
    dirname(__DIR__),
    null,
    ['bypass_shell' => true],
);
if (!is_resource($process)) {
    throw new RuntimeException('Não foi possível iniciar o servidor de teste.');
}
fclose($pipes[0]);

try {
    $ready = false;
    for ($attempt = 0; $attempt < 50; ++$attempt) {
        $connection = @stream_socket_client('tcp://' . $address, $errorCode, $errorMessage, 0.1);
        if ($connection !== false) {
            fclose($connection);
            $ready = true;
            break;
        }
        usleep(100_000);
    }
    $check($ready, 'Servidor HTTP disponível');
    $request = static function (string $method, string $body = '', string $query = '', string $type = 'application/json', int $status = 200, bool $includeFiles = false) use ($address, $check): array {
        $context = stream_context_create(['http' => [
            'method' => $method,
            'header' => "Content-Type: $type\r\nCookie: value=cookie-pollution\r\nX-Test-Include-Files: " . (int) $includeFiles . "\r\n",
            'content' => $body,
            'timeout' => 5,
            'ignore_errors' => true,
        ]]);
        $response = file_get_contents('http://' . $address . '/?' . $query, false, $context);
        if ($response === false) {
            throw new RuntimeException('Falha na requisição HTTP.');
        }
        $check(str_contains($http_response_header[0], ' ' . $status . ' '), 'Status HTTP esperado: ' . $status);
        return json_decode($response, true, flags: JSON_THROW_ON_ERROR);
    };

    $data = $request('GET', query: 'value=%3Cb%3EAna%3C%2Fb%3E');
    $check($data['getValue'] === '&lt;b&gt;Ana&lt;/b&gt;', 'Filtro GET real');
    $check($data['requestValue'] === $data['getValue'], 'Filtro REQUEST real');
    $check($data['missingValue'] === null, 'Filtro de chave ausente');
    $check($data['post'] === null && $data['put'] === null && $data['delete'] === null, 'Métodos incompatíveis');
    $check($request('GET')['get'] === [], 'GET vazio');
    $check($request('GET', query: 'value%5B%5D=a')['getValue'] === false, 'GET com array');
    $check($request('GET')['requestValue'] === null, 'Cookie não cria valor REQUEST');
    $check($request('GET', query: 'value=Ana')['requestValue'] === 'Ana', 'Cookie não sobrescreve GET');
    $check($request('GET', query: 'value=%F0%9F%98%80')['getValue'] === '😀', 'UTF-8 independente do charset global');
    $check($request('GET', query: 'value=%FF', status: 400)['error'] === 'invalid_input', 'Rejeitar UTF-8 inválido em GET');
    $check($request('GET', query: 'value=%26lt%3Bscript%26gt%3B')['getValue'] === '&amp;lt;script&amp;gt;', 'Codificar entidades já presentes');
    $data = $request('POST', 'value=%3Cb%3EAna%3C%2Fb%3E', type: 'application/x-www-form-urlencoded');
    $check($data['postValue'] === '&lt;b&gt;Ana&lt;/b&gt;', 'Filtro POST real');
    $data = $request('POST', 'value=post', 'value=get', 'application/x-www-form-urlencoded');
    $check($data['requestValue'] === 'post', 'POST prevalece sobre GET e cookie');
    $data = $request('POST', 'value%5B%5D=x', 'value=get', 'application/x-www-form-urlencoded');
    $check($data['requestValue'] === false, 'POST inválido não recua para GET');
    foreach (['POST' => 'post', 'PUT' => 'put', 'DELETE' => 'delete'] as $method => $key) {
        $data = $request($method, '{"name":"Ana","nested":{"attack":"<script>alert(1)</script>"}}');
        $check($data[$key]['name'] === 'Ana', "$method JSON");
        $check(!str_contains($data[$key]['nested']['attack'], '<script>'), "$method sanitização");
        $check($request($method)[$key] === [], "$method corpo vazio");
        foreach (['{invalid', 'null', '42', '"text"', '{"value":"' . "\xFF" . '"}'] as $body) {
            $check($request($method, $body, status: 400)['error'] === 'invalid_input', "$method JSON inválido ou escalar");
        }
        $check($request($method, '{"_files":{"tmp_name":"/etc/passwd"}}', status: 400)['error'] === 'invalid_input', "$method _files falsificado");
        $check($request($method, '{"a":{"b":{"c":{"d":{"e":1}}}}}', status: 413)['error'] === 'input_limit', "$method profundidade");
        $check($request($method, json_encode(range(1, 13)), status: 413)['error'] === 'input_limit', "$method quantidade");
        $check($request($method, '{"v":"' . str_repeat('x', 257) . '"}', status: 413)['error'] === 'input_limit', "$method tamanho real do corpo");
        $check($request($method, '{"v":1}', type: 'text/plain', status: 400)['error'] === 'invalid_input', "$method Content-Type incompatível");
        $typed = $request($method, '{"n":42,"b":false,"v":null,"id":9223372036854775808}', type: 'application/problem+json; charset=UTF-8')[$key];
        $check($typed === ['n' => 42, 'b' => false, 'v' => null, 'id' => '9223372036854775808'], "$method preservar tipos e inteiros grandes");
        $check($request($method, str_repeat('[', 10) . '0' . str_repeat(']', 10), status: 400)['error'] === 'invalid_input', "$method profundidade do decoder");
    }
    $boundary = 'InputSecurityTestBoundary';
    $multipart = "--$boundary\r\nContent-Disposition: form-data; name=\"document\"; filename=\"evil<script>.txt\"\r\nContent-Type: text/plain\r\n\r\ncontents\r\n--$boundary--\r\n";
    $type = 'multipart/form-data; boundary=' . $boundary;
    $data = $request('POST', $multipart, type: $type);
    $check($data['post'] === [], 'Upload real não expõe caminho temporário nem nome do cliente');
    $data = $request('POST', $multipart, type: $type, includeFiles: true);
    $file = $data['post']['_files']['document'];
    $check($file['error'] === UPLOAD_ERR_OK && $file['tmp_name'] !== '', 'Upload real disponível por opção explícita');
    $check($file['name'] === 'evil<script>.txt', 'Metadados explícitos permanecem brutos para processamento');
    $spoofedMultipart = "--$boundary\r\nContent-Disposition: form-data; name=\"_files\"\r\n\r\nfake\r\n" . $multipart;
    $data = $request('POST', $spoofedMultipart, type: $type, status: 400, includeFiles: true);
    $check($data['error'] === 'invalid_input', 'Upload real não permite campo _files falsificado');
    echo "$checks verificações passaram em PHP " . PHP_VERSION . PHP_EOL;
} finally {
    proc_terminate($process);
    proc_close($process);
    unlink($log);
}
