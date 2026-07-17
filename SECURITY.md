# Publicacao segura

O Anhangá Recorder controla cameras e armazena credenciais de acesso. Nao exponha a porta HTTP do Python diretamente na internet. A configuracao recomendada e:

```text
Internet -> HTTPS/reverse proxy -> 127.0.0.1:8088 -> Anhangá Recorder
```

## Antes de publicar

1. Inicie o app apenas em `127.0.0.1`, acesse localmente e defina uma senha web forte.
2. Mantenha `data/config.json` fora de backups publicos e repositorios. No Linux, o app aplica modo `0600` ao arquivo e `0700` ao diretorio.
3. Execute o servico com o usuario sem privilegios `anhanga-recorder`, conforme `camera-recorder.service`.
4. Libere no firewall somente a porta HTTPS do proxy. A porta `8088` deve permanecer acessivel apenas pelo host local.
5. Restrinja no proxy o tamanho do corpo, a taxa de requisicoes e o tempo das conexoes.

## Exemplo Nginx

A diretiva `limit_req_zone` fica dentro do bloco `http` principal do Nginx:

```nginx
limit_req_zone $binary_remote_addr zone=anhanga_recorder:10m rate=120r/m;
```

Exemplo de servidor HTTPS:

```nginx
server {
    listen 443 ssl;
    server_name recorder.example.com;

    ssl_certificate /etc/letsencrypt/live/recorder.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/recorder.example.com/privkey.pem;

    client_max_body_size 1m;
    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {
        limit_req zone=anhanga_recorder burst=30 nodelay;
        proxy_pass http://127.0.0.1:8088;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 60s;
    }

    location ^~ /api/preview/ {
        limit_req zone=anhanga_recorder burst=10 nodelay;
        proxy_pass http://127.0.0.1:8088;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 1900s;
    }
}
```

O proxy deve preservar `Host`; ele e usado para validar o cabecalho `Origin`. O app so confia em `X-Forwarded-For` quando a conexao vem de loopback.

## TLS direto

Quando nao houver reverse proxy, o servidor pode terminar TLS diretamente:

```bash
python3 server.py \
  --host 0.0.0.0 \
  --port 8443 \
  --tls-cert /etc/ssl/certs/recorder.crt \
  --tls-key /etc/ssl/private/recorder.key
```

Uma senha web deve estar configurada antes dessa inicializacao. `--allow-insecure-http` existe somente para testes conscientes em redes privadas e nao deve ser usado para publicacao na internet.

## Controles incorporados

- Senhas web armazenadas com PBKDF2-SHA256.
- Segredos T2U/P2P/RTSP e URLs autenticadas omitidos das respostas da API.
- Validacao de origem em operacoes mutaveis e requisicoes de API vindas de navegador.
- Bloqueio temporario depois de 10 falhas de autenticacao em 5 minutos por cliente.
- Limite global, por cliente e por duracao para previews MJPEG/FFmpeg.
- Cabecalhos CSP, `nosniff`, `DENY`, politica de referenciador e HSTS quando o TLS e direto.
- Caminhos de executaveis, DLLs e gravacoes controlados apenas pela configuracao local.

Esses controles complementam HTTPS, firewall, atualizacoes do sistema e monitoramento. Eles nao substituem essas camadas.
