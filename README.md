# MarketMedia Input

Biblioteca para leitura e sanitização de entradas HTTP, com autoload PSR-4 e PHP `^8.5`.

## Instalação local

No projeto consumidor, registre este diretório como repositório Composer:

```json
{
    "repositories": [
        {
            "type": "path",
            "url": "../input",
            "options": { "versions": { "market-media/input": "1.0.0" } }
        }
    ]
}
```

Ajuste `url` para o caminho desta biblioteca e execute:

```sh
composer require market-media/input:^1.0
```

O pacote ainda não foi publicado no Packagist.

## Uso

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use MarketMedia\Input\Input;

$input = new Input();
$data = $input->post();
$search = $input->getValue('search');
```

| Método | Comportamento |
| --- | --- |
| `get()` | Retorna `$_GET` sanitizado em requisições GET. |
| `post()` | Retorna `$_POST` ou corpo JSON sanitizado em requisições POST. |
| `put()` | Retorna `$_POST` ou corpo JSON sanitizado em requisições PUT. |
| `delete()` | Retorna o corpo JSON sanitizado em requisições DELETE. |
| `getValue($key)` | Filtra um valor GET usando `filter_input`. |
| `postValue($key)` | Filtra um valor POST usando `filter_input`. |
| `requestValue($key)` | Lê POST e depois GET, sem consultar cookies ou `$_REQUEST`. |
| `serverValue($key)` | Filtra um valor SERVER usando `filter_input`. |

Os métodos de requisição retornam `null` quando o método HTTP não corresponde ou não está definido. Corpo vazio resulta em `[]`. JSON inválido, escalar, com UTF-8 inválido ou profundo demais é rejeitado com `UnexpectedValueException`. Corpos JSON exigem `application/json` ou `application/*+json`; parâmetros no Content-Type são aceitos.

POST e PUT não incluem uploads por padrão. Para processá-los, use `$input->post(includeFiles: true)` ou `$input->put(includeFiles: true)`: `_files` conterá os metadados brutos de `$_FILES`, incluindo caminhos temporários. Não serialize esse resultado em respostas públicas. Um campo `_files` enviado pelo cliente na raiz dos dados é sempre rejeitado.

Os métodos de valor retornam `string|false|null`: `null` para chave ausente e `false` para valores em array ou UTF-8 inválido. Usam os valores originais recebidos pelo PHP (`filter_input`), sem considerar alterações posteriores nas superglobais, e codificam texto HTML com `htmlspecialchars`, aspas e UTF-8 explícito. Entidades já presentes também são codificadas. `requestValue` prioriza POST, mesmo quando o valor POST é inválido, sem recuar para GET nesse caso.

PUT lê `$_POST` quando preenchido e, caso contrário, JSON. Não faz parsing de formulários PUT. Uploads sem campos são tratados como dados vazios, sem tentar interpretar o multipart bruto como JSON. A sanitização dos valores de texto nos arrays usa `voku/anti-xss`; números, booleanos e `null` mantêm seus tipos. Inteiros JSON maiores que a capacidade do PHP são preservados como strings.

## Limites e segurança

```php
$input = new Input(
    maxBodyBytes: 1_048_576,
    maxDepth: 32,
    maxFields: 1000,
);
```

Esses são os limites padrão. A leitura do corpo JSON é limitada antes da decodificação, independentemente de Content-Length. Antes da sanitização, arrays de GET, POST e JSON são validados por profundidade, quantidade total de campos e soma dos bytes de chaves e valores de texto. Métodos de valor limitam o tamanho da string. Chaves com NUL, UTF-8 inválido e tipos não suportados são rejeitados. Limites excedidos geram `LengthException`; configuração inválida gera `InvalidArgumentException`.

A aplicação deve tratar essas exceções, por exemplo retornando HTTP 400 para `UnexpectedValueException` e HTTP 413 para `LengthException`, com mensagens públicas genéricas e sem stack traces. Uma falha de leitura do corpo gera `RuntimeException`.

Os limites desta classe atuam após o PHP receber a requisição. Configure também os limites do servidor e do PHP (`post_max_size`, `upload_max_filesize`, `max_input_vars`, `max_input_nesting_level`), especialmente para formulários e arquivos. A classe não limita nem valida o conteúdo dos uploads: valide erro, tamanho, MIME real e tipos permitidos; gere o nome de destino no servidor e use `move_uploaded_file` para armazená-los fora da raiz pública.

A sanitização anti-XSS não substitui escape no destino: use escape contextual no template, consultas SQL parametrizadas e evite concatenar entradas em comandos de shell. Chaves permanecem com os nomes originais e também são dados não confiáveis; valide os campos permitidos e não use os arrays diretamente em operações de mass assignment. A classe não implementa autenticação, autorização ou proteção CSRF, e a verificação de Content-Type não substitui essas proteções. Referências: [OWASP — XSS](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) e [PHP — uploads](https://www.php.net/manual/en/features.file-upload.php).

## Migração

Substitua `use App\Supports\Input;` por `use MarketMedia\Input\Input;` e carregue `vendor/autoload.php` em vez de incluir o antigo `Input.php`. A propriedade protegida e os retornos dos métodos de valor possuem tipos explícitos.

Após a revisão de segurança, trate as exceções de entrada inválida e limites excedidos; envie JSON com Content-Type adequado; habilite uploads explicitamente quando necessários e remova dependências da antiga leitura de cookies por `requestValue`. Atualize também subclasses que sobrescrevam `post`, `put` ou o construtor para acompanhar as novas assinaturas.

## Desenvolvimento

Com PHP 8.5 no PATH:

```sh
composer install
composer validate
composer test
```
