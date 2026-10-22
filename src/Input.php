<?php

declare(strict_types=1);

namespace MarketMedia\Input;

use InvalidArgumentException;
use JsonException;
use LengthException;
use RuntimeException;
use UnexpectedValueException;
use voku\helper\AntiXSS;

/**
 * Leitura HTTP com limites de processamento e sanitização anti-XSS.
 * Os resultados ainda exigem validação de domínio e escape no destino.
 */
class Input
{
    /**
     * @var AntiXSS
     */
    protected AntiXSS $antiXss;

    /**
     * @param int $maxBodyBytes
     * @param int $maxDepth
     * @param int $maxFields
     */
    public function __construct(
        private readonly int $maxBodyBytes = 1_048_576,
        private readonly int $maxDepth = 32,
        private readonly int $maxFields = 1000,
    ) {
        if ($maxBodyBytes < 1 || $maxBodyBytes === PHP_INT_MAX
            || $maxDepth < 1 || $maxDepth > 512 || $maxFields < 1) {
            throw new InvalidArgumentException('Limites de entrada inválidos.');
        }

        $this->antiXss = new AntiXSS();
    }

    /** Metadados de uploads são incluídos somente quando solicitados. */
    public function post(bool $includeFiles = false): ?array
    {
        return $this->bodyFor('POST', $includeFiles);
    }

    /**
     * @return array|null
     */
    public function get(): ?array
    {
        return $this->isMethod('GET') ? $this->sanitize($_GET) : null;
    }

    /** Metadados de uploads são incluídos somente quando solicitados. */
    public function put(bool $includeFiles = false): ?array
    {
        return $this->bodyFor('PUT', $includeFiles);
    }

    /**
     * @return array|null
     */
    public function delete(): ?array
    {
        return $this->isMethod('DELETE') ? $this->sanitize($this->getJsonPayload()) : null;
    }

    /**
     * @param string $method
     * @return bool
     */
    private function isMethod(string $method): bool
    {
        return ($_SERVER['REQUEST_METHOD'] ?? null) === $method;
    }

    /**
     * @param string $method
     * @param bool $includeFiles
     * @return array|null
     */
    private function bodyFor(string $method, bool $includeFiles): ?array
    {
        if (!$this->isMethod($method)) {
            return null;
        }

        // Não interpretar o multipart bruto como JSON em uploads sem campos.
        $data = $_POST !== [] ? $_POST : ($_FILES !== [] ? [] : $this->getJsonPayload());
        $data = $this->sanitize($data);

        if ($includeFiles && $_FILES !== []) {
            // Dados brutos necessários ao upload. Não são seguros para exibição.
            $data['_files'] = $_FILES;
        }

        return $data;
    }

    /**
     * @return array
     */
    private function getJsonPayload(): array
    {
        // Leitura limitada, sem confiar no Content-Length informado pelo cliente.
        $payload = file_get_contents('php://input', false, null, 0, $this->maxBodyBytes + 1);
        if ($payload === false) {
            throw new RuntimeException('Não foi possível ler o corpo da requisição.');
        }
        if (strlen($payload) > $this->maxBodyBytes) {
            throw new LengthException('Corpo da requisição excede o limite permitido.');
        }
        if ($payload === '') {
            return [];
        }

        $contentType = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
        if (preg_match('~^application/(?:json|[a-z0-9!#$&^_.+-]+\+json)$~D', $contentType) !== 1) {
            throw new UnexpectedValueException('Corpo JSON exige Content-Type application/json ou application/*+json.');
        }

        try {
            $decoded = json_decode($payload, true, $this->maxDepth + 2, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (JsonException $exception) {
            throw new UnexpectedValueException('JSON inválido ou profundo demais.', previous: $exception);
        }
        if (!is_array($decoded)) {
            throw new UnexpectedValueException('O corpo JSON deve ser um objeto ou array.');
        }

        return $decoded;
    }

    /**
     * @param array $data
     * @return array
     */
    private function sanitize(array $data): array
    {
        // Impede que campos do cliente sejam confundidos com uploads reais.
        if (array_key_exists('_files', $data)) {
            throw new UnexpectedValueException('O campo _files é reservado para uploads.');
        }

        $fields = 0;
        $bytes = 0;
        // Valida toda a estrutura antes de chamar o sanitizador recursivo.
        $this->validateStructure($data, 1, $fields, $bytes);

        return $this->cleanValues($data);
    }

    /**
     * @param array $data
     * @param int $depth
     * @param int $fields
     * @param int $bytes
     * @return void
     */
    private function validateStructure(array $data, int $depth, int &$fields, int &$bytes): void
    {
        if ($depth > $this->maxDepth) {
            throw new LengthException('Entrada excede a profundidade permitida.');
        }
        foreach ($data as $key => $value) {
            if (++$fields > $this->maxFields) {
                throw new LengthException('Entrada excede a quantidade de campos permitida.');
            }
            $bytes += strlen((string) $key);
            if ($bytes > $this->maxBodyBytes) {
                throw new LengthException('Entrada excede o tamanho permitido.');
            }
            if (is_string($key) && (str_contains($key, "\0") || preg_match('//u', $key) !== 1)) {
                throw new UnexpectedValueException('Chave de entrada inválida.');
            }
            if (is_string($value)) {
                $bytes += strlen($value);
                if ($bytes > $this->maxBodyBytes) {
                    throw new LengthException('Entrada excede o tamanho permitido.');
                }
                if (preg_match('//u', $value) !== 1) {
                    throw new UnexpectedValueException('Entrada deve usar UTF-8 válido.');
                }
            } elseif (!is_array($value) && !is_scalar($value) && $value !== null) {
                throw new UnexpectedValueException('Tipo de entrada inválido.');
            }
            if (is_array($value)) {
                $this->validateStructure($value, $depth + 1, $fields, $bytes);
            }
        }
    }

    /**
     * @param array $data
     * @return array
     */
    private function cleanValues(array $data): array
    {
        foreach ($data as &$value) {
            if (is_array($value)) {
                $value = $this->cleanValues($value);
            } elseif (is_string($value)) {
                // Preserva números, booleanos e null de documentos JSON.
                $value = $this->antiXss->xss_clean($value);
            }
        }
        unset($value);

        return $data;
    }

    /**
     * @param string $key
     * @return string|false|null
     */
    public function postValue(string $key): string|false|null
    {
        return $this->encodeValue(filter_input(INPUT_POST, $key, FILTER_UNSAFE_RAW));
    }

    /**
     * @param string $key
     * @return string|false|null
     */
    public function getValue(string $key): string|false|null
    {
        return $this->encodeValue(filter_input(INPUT_GET, $key, FILTER_UNSAFE_RAW));
    }

    /** POST tem precedência sobre GET; cookies não participam desta leitura. */
    public function requestValue(string $key): string|false|null
    {
        if (filter_has_var(INPUT_POST, $key)) {
            return $this->postValue($key);
        }

        return $this->getValue($key);
    }

    /**
     * @param string $key
     * @return string|false|null
     */
    public function serverValue(string $key): string|false|null
    {
        return $this->encodeValue(filter_input(INPUT_SERVER, $key, FILTER_UNSAFE_RAW));
    }

    /**
     * @param string|false|null $value
     * @return string|false|null
     */
    private function encodeValue(string|false|null $value): string|false|null
    {
        if (!is_string($value)) {
            return $value;
        }
        if (strlen($value) > $this->maxBodyBytes) {
            throw new LengthException('Valor excede o tamanho permitido.');
        }
        if (preg_match('//u', $value) !== 1) {
            return false;
        }

        // Charset explícito e entidades sempre codificadas para texto HTML.
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
