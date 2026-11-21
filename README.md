# Estoque IA

Aplicativo de gestão de estoque, PDV e assinaturas. O servidor Node.js serve a página comercial e o app. As migrações versionadas do PostgreSQL são aplicadas ao iniciar.

## Implantação

- Instale as dependências com `npm install` e inicie com `npm start`.
- Configure `DATABASE_URL`, `JWT_SECRET`, `NODE_ENV=production` e o health check do Render em `/health`.
- Para atualizar uma instalação existente, preserve o banco e teste a migração `004_billing_sync.sql` em uma cópia restaurada primeiro. Confirme no banco de destino os registros de empresas, produtos e vendas antes de trocar a conexão da aplicação.

## Assinaturas Mercado Pago

A contratação de novas assinaturas começa desativada. A API só a habilita com `MP_CHECKOUT_ENABLED=true`, as credenciais `MP_PUBLIC_KEY`, `MP_ACCESS_TOKEN`, `MP_WEBHOOK_SECRET` e ao menos um dos IDs `MP_PLAN_BASICO_ID`, `MP_PLAN_PRO_ID`, `MP_PLAN_PREMIUM_ID`. Configure somente planos de recorrência mensal em BRL com o preço exibido no site.

Use `MP_TEST_MODE=true` e credenciais e IDs de planos de teste em uma implantação separada. `MP_TEST_PAYER_EMAIL` é opcional e só é usado nesse modo. Configure no Mercado Pago o webhook HTTPS em `/webhooks/mercadopago` para eventos de assinatura e cobrança recorrente. Guarde as credenciais nas variáveis do serviço.

Antes de ativar a contratação em produção, confirme no ambiente de teste que um pagamento aprovado ativa o plano, uma renovação confirmada estende o acesso apenas uma vez, um pagamento recusado não estende o prazo e o cancelamento confirmado atualiza o app. Confira também cadastro, login, uma venda e o respectivo estorno. Depois, publique com as credenciais de produção e verifique `/health`.

Se uma contratação ficar aguardando confirmação após uma falha de rede, procure no Mercado Pago a referência externa formada pelo ID da empresa e pelo `billing_checkout_id`, unidos por dois-pontos. A notificação do Mercado Pago pode concluir a vinculação. Só limpe a reserva depois de confirmar com o provedor que a tentativa não criou assinatura. Uma tentativa em aberto impede nova cobrança para a mesma empresa.

## Produtos da versão offline

No Estoque IA offline, use **Exportar backup** para gerar o JSON. No sistema web, entre como administrador, abra **Posição de estoque → Importar produtos da versão offline** e selecione o arquivo. Confira a quantidade de produtos e confirme na empresa de destino. A importação repõe o cadastro e o saldo inicial de SKUs ausentes, sem sobrescrever SKUs existentes. Dados de clientes, usuários, filiais e vendas permanecem no backup completo.
