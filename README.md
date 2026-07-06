# Anhangá Recorder

Aplicacao local acessada pelo navegador para gravar em disco cameras ou entradas selecionadas. O caminho mais portavel e confiavel continua sendo FFmpeg diretamente nos streams RTSP. Tambem ha um modo experimental `Cloud/P2P` usando uma biblioteca T2U para abrir um tunel local antes de chamar o FFmpeg.

## O que ela faz

- Grava todas as fontes cadastradas ou apenas as selecionadas.
- Usa `-c copy` no FFmpeg para preservar a qualidade original de video/audio, sem recompressao.
- Segmenta a gravacao em arquivos `.mkv`, por fonte e por data.
- Reinicia streams automaticamente quando uma conexao cai.
- Permite cadastrar URLs RTSP, HTTP/HTTPS, RTMP, SRT ou outros protocolos suportados pelo FFmpeg.
- Inclui um gerador de URL RTSP no formato comum:
  `rtsp://usuario:senha@host:554/cam/realmonitor?channel=1&subtype=0`
- Tambem aceita dispositivos locais Linux via V4L2, como `/dev/video0`, e audio ALSA opcional.
- Pode testar Cloud/P2P via T2U mapeando uma porta remota do dispositivo para `127.0.0.1`.

## Requisitos

No Linux:

```bash
sudo apt update
sudo apt install -y python3 ffmpeg build-essential
```

Para compilar a biblioteca T2U Linux local:

```bash
cd native/libt2u_linux
make
```

No Windows para Cloud/P2P:

- FFmpeg instalado e configurado no PATH, ou com caminho absoluto configurado na tela.
- SDK T2U com `libt2u.dll` na pasta do projeto ou o caminho da DLL configurado na tela.
- Se a DLL for `x86 / PE32`, use Python 32-bit. Se tiver uma DLL x64, use Python 64-bit.

## Biblioteca T2U

O modo `Cloud/P2P` usa a ABI T2U (`libt2u`). No Linux, este repositorio inclui uma biblioteca de compatibilidade em `native/libt2u_linux`, com tunel TCP direto funcional quando o endereco remoto e alcancavel pela rede e suporte experimental P2P/NAT reconstruido a partir da biblioteca Android. A interoperabilidade P2P ainda precisa ser validada com o servidor T2U e cameras reais do ambiente autorizado.

No Windows, o modo depende de uma biblioteca de terceiros (`libt2u.dll`). Essa biblioteca nao faz parte deste projeto, nao e redistribuida neste repositorio e deve ser obtida separadamente pelo usuario, respeitando a licenca e os termos do fornecedor da SDK.

Download oficial da SDK T2U/P2P:

```text
http://www.vveye.com/SDK_Download.html?id=P2P%E7%A9%BF%E9%80%8F%E5%BA%93SDK
```

## Rodar

Na pasta do projeto:

```bash
python3 server.py --host 127.0.0.1 --port 8088
```

Abra:

```text
http://127.0.0.1:8088
```

Por padrao, as gravacoes ficam em `recordings`.

No Windows com DLL T2U 32-bit:

```powershell
py -3-32 server.py --host 127.0.0.1 --port 8088
```

## Autenticacao

A interface web usa autenticacao HTTP Basic. Na primeira execucao, se nenhuma senha estiver configurada, o acesso padrao e:

```text
Usuario: admin
Senha: deixe em branco
```

Depois de acessar, altere em `Gravacao > Acesso`:

- `Usuario`: nome usado para entrar na pagina.
- `Nova senha`: nova senha da interface web, com limite de 50 caracteres.

A senha nao e gravada em texto plano. Quando a configuracao e salva, o app armazena um hash PBKDF2-SHA256 em `data/config.json`. Se uma senha curta for colocada manualmente nesse arquivo, ela sera convertida automaticamente para hash na proxima carga da configuracao.

## Cloud/P2P

Na tela `T2U Clouds`, configure:

- `Biblioteca T2U`: caminho da `libt2u.so` no Linux ou da `libt2u.dll` no Windows.
- `Servidor`, `Porta`, `Chave do servidor` e `Senha T2U/P2P padrao`: valores do ambiente T2U que voce esta autorizado a usar.
- `Timeout T2U`: tempo maximo para conectar ao servidor e abrir o tunel.

Depois, em `Grupos Cloud/P2P`, configure os dados comuns ao dispositivo:

- `T2U Cloud`: ambiente T2U usado pelo grupo.
- `Maximo de fontes permitidas`: `0` para ilimitado ou um numero para limitar quantas fontes do grupo podem iniciar ao mesmo tempo.
- `ID do dispositivo P2P`: identificador usado pela rede P2P, como serial, UID ou UUID do dispositivo.
- `Porta remota`: use `554` para RTSP via FFmpeg.
- `IP remoto`: normalmente `127.0.0.1`.
- `Porta local`: `0` deixa a SDK escolher uma porta livre.
- `Usuario RTSP` e `Senha RTSP`.

Ao cadastrar uma fonte `Cloud/P2P`, selecione o grupo e informe apenas o `Caminho RTSP`, por exemplo:

```text
/cam/realmonitor?channel=1&subtype=0
```

O app abre o tunel com `t2u_add_port_v3(...)`, aguarda `t2u_port_status(...) > 0`, monta uma URL como `rtsp://usuario:senha@127.0.0.1:<porta-local>/...` e passa essa URL para o FFmpeg. Ao parar a gravacao, chama `t2u_del_port(...)`.

Esse ID P2P e usado somente no modo `Cloud/P2P`. Para conexoes RTSP diretas, use a URL/IP, porta, usuario e senha da fonte.

## Qualidade maxima

O perfil padrao grava com copia direta:

```text
-map 0:v? -map 0:a? -c:v copy -c:a copy
```

Isso preserva codec, resolucao, FPS, bitrate e audio que chegam da camera. Use o stream principal (`subtype=0`) quando quiser a melhor qualidade. O stream extra (`subtype=1`) normalmente e mais leve e tem menor resolucao/bitrate.

## Reconexao

- Falha isolada de uma fonte: nova tentativa a cada 5 minutos.
- Falha de todas as fontes ativas de um mesmo grupo Cloud/P2P: nova tentativa em 5 minutos, dobrando a cada rodada com erro ate o maximo de 1 hora.
- Falha de conexao com o servidor T2U: nova tentativa em 5 minutos, dobrando a cada erro ate o maximo de 1 hora.
- Uma fonte so zera o backoff do grupo depois que o FFmpeg permanece ativo por uma janela curta de estabilidade.

## Servico systemd

Exemplo de instalacao:

```bash
sudo mkdir -p /opt/anhanga-recorder
sudo cp -r . /opt/anhanga-recorder
sudo cp camera-recorder.service /etc/systemd/system/anhanga-recorder.service
sudo systemctl daemon-reload
sudo systemctl enable --now anhanga-recorder
```

Se publicar a interface fora do `127.0.0.1`, coloque autenticacao e firewall na frente. O app armazena URLs de cameras em `data/config.json`, que podem conter credenciais.
