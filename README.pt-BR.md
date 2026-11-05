# Inotify Convergence Lab

Versão de desenvolvimento **0.1.0** — software original da [Lofrano Tecnologia](https://lofranotecnologia.com.br).

Biblioteca C17 e aplicação Linux com fixtures fechadas e verificações obrigatórias. Usa inotify real, renomeações reais, cookies de movimento, enumeração relativa a descritores e SHA-256 via OpenSSL EVP. **Não é um scanner do host**: cada instância cria uma árvore privada e uma quarentena irmã não monitorada dentro de `/tmp/icl-XXXXXX`. Não existe opção para selecionar árvores existentes.

Repositório: https://github.com/martinlofranodeoliveira/inotify-convergence-lab

[English](README.md) · [Contrato preciso](docs/contract.md) · [Projeto](docs/design.md)

## Instalação, testes e demonstração

Requisitos: Linux, GCC 14, Make, cabeçalhos de desenvolvimento OpenSSL 3 e libcrypto. Execute os testes com usuário não root. A biblioteca, os testes e a demonstração não usam rede. Em uma máquina já provisionada:

```sh
make
make test
make sanitize
make demo-assert
build/icl-demo --json
make package
make install PREFIX="$HOME/.local"
```

O pacote de fontes fica em `build/inotify-convergence-lab-0.1.0.tar.gz`. A instalação grava executável, biblioteca estática e cabeçalho no prefixo escolhido; não registra serviço. Aplicações consumidoras vinculam `libicl.a` com `-lcrypto`.

Alternativa isolada com o Dockerfile fornecido:

```sh
docker build --tag icl-dev .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --memory 1g --cpus 2 --user 1000:1000 icl-dev make test sanitize demo-assert package
```

A construção da imagem precisa acessar pacotes; a execução dos testes não. O Dockerfile é uma receita conveniente, não uma imagem offline fixada nem um arquivo de versões travadas. Para reprodução exata, prepare e retenha uma imagem offline verificada separadamente. Nenhuma árvore do host é montada.

O ambiente selecionado informado para qualificação foi GCC 14.3.0 e OpenSSL 3.0.16 (pacote `libssl-dev` `3.0.16-1~deb12u1`) em imagem local `gcc:14-bookworm`. O relato fornecido cobriu EVP SHA-256 de `ab`, criação/renomeação/remoção relativas a descritores e criação/leitura reais de inotify sob UID 1000, sem rede e com capacidades removidas. São observações de ambiente fornecidas na descrição do projeto, não resultados da suíte deste projeto. Nenhum digest completo de artefato foi fornecido aqui para reprodução. A receita pode resolver outros pacotes. Não se afirma comportamento entre kernels, versão mais recente, desempenho ou prontidão para produção.

## Saída esperada

A demonstração termina com código diferente de zero em caso de falha de verificação, limpeza ou saída. Exemplo esperado em caso de sucesso:

```text
Inotify Convergence Lab 0.1.0 (development)
initial: current files=2 directories=1 bytes=3
rename-append: current files=2 directories=1 bytes=5
replacement: current files=2 directories=1 bytes=4
directory-rename: current files=2 directories=1 bytes=4
quarantine: current files=1 directories=1 bytes=1
simulated-overflow-recovery: current files=2 directories=1 bytes=5 overflow=simulated
native-watch-recovery: current files=2 directories=1 bytes=5
symlink-recovery: current files=2 directories=1 bytes=5
event-budget-recovery: current files=2 directories=1 bytes=5
Native watch failure, symlink rejection and event-budget exhaustion: checked
Independent oracle and content assertions: passed
```

Este exemplo não declara execução já realizada. `--json` produz um objeto JSON com `development_version`, `assertions`, nove `stages`, três `negative_checks` e dois `final_files` ordenados com tamanho e SHA-256. O mapa final contém `d.txt` com `z` e `renamed/c.txt` com `1234`. Não inclui tempos, nomes aleatórios das fixtures nem contagens de eventos dependentes de coalescência. O overflow é identificado como **simulado**, nunca como overflow observado do kernel.

## Exemplo de biblioteca

```c
#include "icl.h"

int exemplo(void)
{
    icl *lab = NULL;
    icl_error erro;
    uint64_t token;
    int resultado = 1;
    if (icl_create(&lab, &erro) != ICL_OK) return 1;
    if (icl_writer_begin(lab, &token) == ICL_OK &&
        icl_writer_put(lab, token, "a.txt", "ab", 2, 0) == ICL_OK &&
        icl_writer_end(lab, token) == ICL_OK &&
        icl_reconcile(lab) == ICL_OK) {
        icl_state estado;
        const icl_snapshot *s = icl_snapshot_get(lab, &estado);
        resultado = !(estado == ICL_STATE_CURRENT && s->files == 1 && s->bytes == 2);
    }
    if (icl_destroy(lab, &erro) != ICL_OK) resultado = 1;
    return resultado;
}
```

`writer_begin` invalida imediatamente o estado atual, antes de qualquer efeito no sistema de arquivos. Operações que falham podem deixar efeitos parciais. Encerre o token válido, remova a fixture inválida quando necessário e reconcilie. Os dados da última publicação ficam intactos até uma publicação bem-sucedida; **o estado separado pode ser dirty ou incomplete**. Consulte ambos.

## Decisões e limitações

Inotify fornece evidências, não um diário transacional. Eventos podem ser combinados, movimentos de diretórios afetam caminhos descendentes e cookies/descritores podem ser ambíguos. Por simplicidade verificável, cada reconciliação cria uma nova instância inotify. A publicação exige escritor encerrado, enumeração/hash completos, cobertura de watches e drenagem dos eventos. Pares de cookies servem apenas como diagnóstico, nunca para modificar incrementalmente o mapa verificado.

A suíte usa um oráculo independente de enumeração/hash, conteúdo esperado fixo, falhas nativas reais de abertura/leitura/rename/watch, descarte de eventos, overflow simulado, tokens antigos, tipos proibidos, esgotamento de trabalho/eventos, limites de namespace e retenção de snapshots antigos. ASan/UBSan fazem o alvo falhar em caso de achados. Esta documentação não declara execução bem-sucedida da suíte.

- Protocolo serial de uma única thread. Escritores externos, inclusive mutações por descritores do oráculo, estão fora do contrato.
- Limites conjuntos de raiz e quarentena: 256 entradas, 64 diretórios não-base, três componentes de caminho, 4096 bytes por arquivo e 1 MiB de conteúdo. A raiz não entra na contagem de diretórios.
- Componentes de 1–32 caracteres ASCII: primeiro letra/dígito; demais letras, dígitos, `.`, `_`, `-`. Apenas caminhos relativos. Links simbólicos, hardlinks e arquivos especiais são rejeitados.
- Sem garantia de observar estados intermediários, gerar overflow real, suportar sistemas de arquivos de rede, recuperação após queda, persistência, durabilidade ou transações do sistema de arquivos. Não há alegação ampla de conformidade com padrões.
- Orçamentos lógicos não garantem disco ou RSS. Prazos monotônicos são verificados entre operações e não interrompem chamadas bloqueadas no kernel. Uma limpeza limitada que falhar pode deixar a fixture privada; nunca amplia sua busca.

Licença MIT, copyright 2026 Lofrano Tecnologia. Contato geral pela [página oficial](https://lofranotecnologia.com.br). Relatos de segurança pelo [canal privado do GitHub](https://github.com/martinlofranodeoliveira/inotify-convergence-lab/security/advisories/new).
