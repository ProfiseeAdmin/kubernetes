locals {
  jumpbox_enabled   = try(var.jumpbox.enabled, false)
  jumpbox_name      = coalesce(try(var.jumpbox.name, null), "jumpbox")
  jumpbox_subnet_id = coalesce(try(var.jumpbox.subnet_id, null), module.vpc.private_subnet_ids[0])
  jumpbox_tags      = merge(var.tags, try(var.jumpbox.tags, {}))
  app_ebs_enabled   = try(var.app_ebs.enabled, true)
  app_ebs_az        = coalesce(try(var.app_ebs.availability_zone, null), var.vpc.azs[0])
  app_ebs_tags      = merge(var.tags, try(var.app_ebs.tags, {}))
  settings_bucket_enabled = try(var.settings_bucket.enabled, true)
  settings_bucket_name    = try(var.settings_bucket.name, null)
  settings_bucket_tags    = merge(var.tags, try(var.settings_bucket.tags, {}))
  platform_deployer_enabled = try(var.platform_deployer.enabled, false)
  platform_deployer_tags    = merge(var.tags, try(var.platform_deployer.tags, {}))
  platform_deployer_settings_key = coalesce(try(var.platform_deployer.settings_key, null), "settings/${var.eks.cluster_name}/Settings.yaml")
  kubeconfig_s3_key = "kubeconfig/${var.eks.cluster_name}/kubeconfig"
  platform_outputs_s3_key = "outputs/${var.eks.cluster_name}/platform.json"
  db_init_enabled = try(var.db_init.enabled, false)
  db_init_tags    = merge(var.tags, try(var.db_init.tags, {}))
}

data "aws_caller_identity" "current" {}

module "vpc" {
  source = "../modules/vpc"

  name                 = var.vpc.name
  cidr_block           = var.vpc.cidr_block
  azs                  = var.vpc.azs
  public_subnet_cidrs  = var.vpc.public_subnet_cidrs
  private_subnet_cidrs = var.vpc.private_subnet_cidrs
  enable_nat_gateway   = var.vpc.enable_nat_gateway
  single_nat_gateway   = var.vpc.single_nat_gateway
  enable_dns_hostnames = var.vpc.enable_dns_hostnames
  enable_dns_support   = var.vpc.enable_dns_support
  public_subnet_tags   = var.vpc.public_subnet_tags
  private_subnet_tags  = var.vpc.private_subnet_tags
  vpc_tags             = var.vpc.vpc_tags
  tags                 = var.vpc.tags
}

resource "aws_s3_bucket" "settings" {
  count = local.settings_bucket_enabled ? 1 : 0

  bucket        = local.settings_bucket_name
  force_destroy = try(var.settings_bucket.force_destroy, false)
  tags          = local.settings_bucket_tags
}

resource "aws_s3_bucket_public_access_block" "settings" {
  count = local.settings_bucket_enabled ? 1 : 0

  bucket                  = aws_s3_bucket.settings[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "settings" {
  count = local.settings_bucket_enabled ? 1 : 0

  bucket = aws_s3_bucket.settings[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "settings" {
  count = local.settings_bucket_enabled ? 1 : 0

  bucket = aws_s3_bucket.settings[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = try(var.settings_bucket.kms_key_arn, null) != null ? "aws:kms" : "AES256"
      kms_master_key_id = try(var.settings_bucket.kms_key_arn, null)
    }
  }
}

module "eks" {
  source = "../modules/eks"

  cluster_name            = var.eks.cluster_name
  cluster_version         = var.eks.cluster_version
  authentication_mode     = var.eks.authentication_mode
  vpc_id                  = module.vpc.vpc_id
  private_subnet_ids      = module.vpc.private_subnet_ids
  public_subnet_ids       = module.vpc.public_subnet_ids
  endpoint_public_access  = var.eks.endpoint_public_access
  endpoint_private_access = var.eks.endpoint_private_access
  enabled_cluster_log_types = var.eks.enabled_cluster_log_types
  cluster_kms_key_arn        = var.eks.cluster_kms_key_arn
  linux_node_group           = var.eks.linux_node_group
  windows_node_group         = var.eks.windows_node_group
  tags                       = var.eks.tags
}

resource "aws_ecs_cluster" "platform_deployer" {
  count = local.platform_deployer_enabled ? 1 : 0

  name = "${var.eks.cluster_name}-platform-deployer"
  tags = local.platform_deployer_tags
}

resource "aws_ecs_cluster" "db_init" {
  count = local.db_init_enabled ? 1 : 0

  name = "${var.eks.cluster_name}-db-init"
  tags = local.db_init_tags
}

resource "aws_cloudwatch_log_group" "db_init" {
  count = local.db_init_enabled ? 1 : 0

  name              = "/aws/ecs/${var.eks.cluster_name}-db-init"
  retention_in_days = 14
  tags              = local.db_init_tags
}

resource "aws_cloudwatch_log_group" "platform_deployer" {
  count = local.platform_deployer_enabled ? 1 : 0

  name              = "/aws/ecs/${var.eks.cluster_name}-platform-deployer"
  retention_in_days = 14
  tags              = local.platform_deployer_tags
}

data "aws_iam_policy_document" "platform_deployer_task_assume" {
  count = local.platform_deployer_enabled ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "platform_deployer_task" {
  count = local.platform_deployer_enabled ? 1 : 0

  name               = "${var.eks.cluster_name}-platform-deployer-task"
  assume_role_policy = data.aws_iam_policy_document.platform_deployer_task_assume[0].json
  tags               = local.platform_deployer_tags
}

data "aws_iam_policy_document" "db_init_task_assume" {
  count = local.db_init_enabled ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "db_init_task" {
  count = local.db_init_enabled ? 1 : 0

  name               = "${var.eks.cluster_name}-db-init-task"
  assume_role_policy = data.aws_iam_policy_document.db_init_task_assume[0].json
  tags               = local.db_init_tags
}

data "aws_iam_policy_document" "platform_deployer_task" {
  count = local.platform_deployer_enabled ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "eks:DescribeCluster",
      "eks:ListClusters"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:ListBucket"
    ]
    resources = local.settings_bucket_enabled ? [
      aws_s3_bucket.settings[0].arn,
      "${aws_s3_bucket.settings[0].arn}/*"
    ] : []
  }

  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue"
    ]
    resources = length(try(var.platform_deployer.secret_arns, {})) > 0 ? values(var.platform_deployer.secret_arns) : ["*"]
  }

  statement {
    effect = "Allow"
    actions = ["kms:Decrypt"]
    resources = try(var.settings_bucket.kms_key_arn, null) != null ? [var.settings_bucket.kms_key_arn] : ["*"]
  }
}

resource "aws_iam_role_policy" "platform_deployer_task" {
  count = local.platform_deployer_enabled ? 1 : 0

  name   = "${var.eks.cluster_name}-platform-deployer-task"
  role   = aws_iam_role.platform_deployer_task[0].id
  policy = data.aws_iam_policy_document.platform_deployer_task[0].json
}

locals {
  db_init_secret_arns = length(try(var.db_init.secret_arns, {})) > 0 ? var.db_init.secret_arns : try(var.platform_deployer.secret_arns, {})
}

data "aws_iam_policy_document" "db_init_task" {
  count = local.db_init_enabled ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue"
    ]
    resources = concat(
      [module.rds_sqlserver.master_user_secret_arn],
      length(local.db_init_secret_arns) > 0 ? values(local.db_init_secret_arns) : []
    )
  }

  statement {
    effect = "Allow"
    actions = [
      "eks:DescribeCluster"
    ]
    resources = [
      "arn:aws:eks:${var.region}:${data.aws_caller_identity.current.account_id}:cluster/${var.eks.cluster_name}"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:ListBucket",
      "s3:GetBucketLocation"
    ]
    resources = local.settings_bucket_enabled ? [
      aws_s3_bucket.settings[0].arn,
      "${aws_s3_bucket.settings[0].arn}/*"
    ] : []
  }

  dynamic "statement" {
    for_each = try(var.route53.hosted_zone_id, "") != "" ? [var.route53.hosted_zone_id] : []
    content {
      effect = "Allow"
      actions = [
        "route53:GetHostedZone",
        "route53:ListResourceRecordSets",
        "route53:ChangeResourceRecordSets"
      ]
      resources = ["arn:aws:route53:::hostedzone/${statement.value}"]
    }
  }

  statement {
    effect = "Allow"
    actions = ["kms:Decrypt"]
    resources = try(var.rds_sqlserver.master_user_secret_kms_key_id, null) != null ? [var.rds_sqlserver.master_user_secret_kms_key_id] : ["*"]
  }

  dynamic "statement" {
    for_each = try(var.settings_bucket.kms_key_arn, null) != null ? [var.settings_bucket.kms_key_arn] : []
    content {
      effect = "Allow"
      actions = [
        "kms:Encrypt",
        "kms:GenerateDataKey"
      ]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_role_policy" "db_init_task" {
  count = local.db_init_enabled ? 1 : 0

  name   = "${var.eks.cluster_name}-db-init-task"
  role   = aws_iam_role.db_init_task[0].id
  policy = data.aws_iam_policy_document.db_init_task[0].json
}

resource "aws_iam_role" "platform_deployer_execution" {
  count = local.platform_deployer_enabled ? 1 : 0

  name               = "${var.eks.cluster_name}-platform-deployer-exec"
  assume_role_policy = data.aws_iam_policy_document.platform_deployer_task_assume[0].json
  tags               = local.platform_deployer_tags
}

resource "aws_iam_role" "db_init_execution" {
  count = local.db_init_enabled ? 1 : 0

  name               = "${var.eks.cluster_name}-db-init-exec"
  assume_role_policy = data.aws_iam_policy_document.db_init_task_assume[0].json
  tags               = local.db_init_tags
}

resource "aws_iam_role_policy_attachment" "db_init_execution" {
  count = local.db_init_enabled ? 1 : 0

  role       = aws_iam_role.db_init_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "db_init_execution" {
  count = local.db_init_enabled && local.db_init_acr_secret_arn != null ? 1 : 0

  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [local.db_init_acr_secret_arn]
  }
}

resource "aws_iam_role_policy" "db_init_execution" {
  count = local.db_init_enabled && local.db_init_acr_secret_arn != null ? 1 : 0

  role   = aws_iam_role.db_init_execution[0].id
  policy = data.aws_iam_policy_document.db_init_execution[0].json
}

resource "aws_iam_role_policy_attachment" "platform_deployer_execution" {
  count = local.platform_deployer_enabled ? 1 : 0

  role       = aws_iam_role.platform_deployer_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_security_group" "platform_deployer" {
  count = local.platform_deployer_enabled ? 1 : 0

  name        = "${var.eks.cluster_name}-platform-deployer-sg"
  description = "Fargate platform deployer egress"
  vpc_id      = module.vpc.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.platform_deployer_tags
}

resource "aws_security_group" "db_init" {
  count = local.db_init_enabled ? 1 : 0

  name        = "${var.eks.cluster_name}-db-init-sg"
  description = "Fargate DB init egress"
  vpc_id      = module.vpc.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.db_init_tags
}

resource "aws_security_group" "traefik_nlb" {
  name        = "${var.eks.cluster_name}-traefik-nlb-sg"
  description = "Traefik NLB security group (managed by OpenTofu)"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.db_init_tags
}

locals {
  platform_deployer_settings_uri = local.settings_bucket_enabled ? "s3://${local.settings_bucket_name}/${local.platform_deployer_settings_key}" : ""
  kubeconfig_s3_uri              = local.settings_bucket_enabled ? "s3://${local.settings_bucket_name}/${local.kubeconfig_s3_key}" : ""
  platform_outputs_s3_uri        = local.settings_bucket_enabled ? "s3://${local.settings_bucket_name}/${local.platform_outputs_s3_key}" : ""
  app_deploy_enabled             = try(var.app_deploy.enabled, false)
  app_deploy_release_name        = try(var.app_deploy.release_name, "profiseeplatform")
  app_deploy_namespace           = try(var.app_deploy.namespace, "profisee")
  platform_deployer_secret_env   = { for k, v in try(var.platform_deployer.secret_arns, {}) : "SECRET_${upper(k)}_ARN" => v }
  platform_deployer_env = merge(
    {
      CLUSTER_NAME     = var.eks.cluster_name
      AWS_REGION       = var.region
      SETTINGS_S3_URI  = local.platform_deployer_settings_uri
      SETTINGS_S3_BUCKET = local.settings_bucket_name
      SETTINGS_S3_KEY  = local.platform_deployer_settings_key
    },
    try(var.platform_deployer.environment, {}),
    local.platform_deployer_secret_env
  )
  db_init_secret_env      = { for k, v in local.db_init_secret_arns : "SECRET_${upper(k)}_ARN" => v }
  db_init_acr_secret_arn  = try(local.db_init_secret_arns["acr"], null)
db_init_command = <<-EOT
set -eo pipefail

LOG_LEVEL="$${DB_INIT_LOG_LEVEL:-info}"
log() { echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*"; }
log_err() { echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*" >&2; }
log_debug() { if [ "$LOG_LEVEL" = "debug" ]; then log "$*"; fi }
run() {
  local desc="$1"
  shift
  log "$desc..."
  if ! "$@" >/tmp/db-init-step.log 2>&1; then
    log "FAILED: $desc"
    sed -n '1,120p' /tmp/db-init-step.log || true
    exit 1
  fi
  log "OK: $desc"
}
trap 'rc=$?; log "Exit code $rc";' EXIT

export ACCEPT_EULA=Y
CURL_RETRY_OPTS="--retry 5 --retry-delay 2 --retry-connrefused --retry-max-time 60"

curl_step() {
  local desc="$1"
  local url="$2"
  local out="$3"
  log "$desc..."
  local http=""
  http=$(curl -sS -L $CURL_RETRY_OPTS -w "%%{http_code}" -o "$out" "$url" 2>/tmp/db-init-step.log)
  local rc=$?
  if [ $rc -ne 0 ]; then
    log "FAILED: $desc (curl exit $rc)"
    sed -n '1,120p' /tmp/db-init-step.log || true
    return 1
  fi
  if [ "$http" -ge 400 ] 2>/dev/null; then
    log "FAILED: $desc (HTTP $http)"
    sed -n '1,120p' /tmp/db-init-step.log || true
    return 1
  fi
  log "OK: $desc"
  log_debug "curl url: $url (http $http)"
  return 0
}

download_tar_gz() {
  local desc="$1"
  local url="$2"
  local out="$3"
  local attempts=3
  local i=1
  while [ $i -le $attempts ]; do
    log "$desc (attempt $i/$attempts)..."
    local http=""
    http=$(curl -sS -L $CURL_RETRY_OPTS -w "%%{http_code}" -o "$out" "$url" 2>/tmp/db-init-step.log)
    local rc=$?
    if [ $rc -ne 0 ]; then
      log "FAILED: $desc (curl exit $rc)"
      sed -n '1,120p' /tmp/db-init-step.log || true
    elif [ "$http" -ge 400 ] 2>/dev/null; then
      log "FAILED: $desc (HTTP $http)"
    elif tar -tzf "$out" >/dev/null 2>&1; then
      log "OK: $desc"
      return 0
    else
      log "FAILED: $desc (invalid tar.gz)"
    fi
    rm -f "$out"
    i=$((i + 1))
    sleep 2
  done
  return 1
}

log "Using prebuilt db-init tools image; skipping tool installation."

export PATH="/opt/mssql-tools18/bin:$PATH"
export AWS_PAGER=""

if [ -z "$AWS_REGION" ] || [ -z "$CLUSTER_NAME" ] || [ -z "$DB_ENDPOINT" ] || [ -z "$DB_NAME" ] || [ -z "$SECRET_RDS_MASTER_ARN" ] || [ -z "$SECRET_SQL_ARN" ]; then
  log "Missing required environment variables."
  exit 1
fi

log "Fetching secrets from Secrets Manager..."
get_secret_json() {
  local arn="$1"
  local label="$2"
  local out
  log_err "Reading secret $label..."
  set +e
  out=$(aws secretsmanager get-secret-value --secret-id "$arn" --region "$AWS_REGION" --query SecretString --output text --no-cli-pager 2>/tmp/secret.err)
  local rc=$?
  set -e
  out=$(printf '%s' "$out" | sed '1s/^\xEF\xBB\xBF//')
  local err
  err=$(cat /tmp/secret.err 2>/dev/null || true)
  if [ $rc -ne 0 ]; then
    if [ -z "$err" ]; then err="<empty>"; fi
    log_err "Failed to read secret $label ($arn): $err"
    if [ -n "$out" ]; then
      log_err "Secret $label stdout (first 120 chars): $(echo "$out" | head -c 120)"
    fi
    return 1
  fi
  if ! echo "$out" | jq -e . >/dev/null 2>&1; then
    log_err "Secret $label is not valid JSON (length $${#out})."
    log_err "Secret $label raw output suppressed."
    return 1
  fi
  echo "$out"
}

MASTER_JSON=$(get_secret_json "$SECRET_RDS_MASTER_ARN" "master") || exit 1
APP_JSON=$(get_secret_json "$SECRET_SQL_ARN" "app-sql") || exit 1

MASTER_USER=$(echo "$MASTER_JSON" | jq -r '.username // empty')
MASTER_PASS=$(echo "$MASTER_JSON" | jq -r '.password // empty')
APP_USER=$(echo "$APP_JSON" | jq -r '.username // empty')
APP_PASS=$(echo "$APP_JSON" | jq -r '.password // empty')

if [ -z "$MASTER_USER" ] || [ -z "$MASTER_PASS" ] || [ -z "$APP_USER" ] || [ -z "$APP_PASS" ]; then
  log "Missing username/password in Secrets Manager payloads."
  exit 1
fi

escape_sql_literal() { printf "%s" "$1" | sed "s/'/''/g"; }
escape_sql_bracket() { printf "%s" "$1" | sed "s/]/]]/g"; }

db_lit=$(escape_sql_literal "$DB_NAME")
db_bracket=$(escape_sql_bracket "$DB_NAME")
app_user_lit=$(escape_sql_literal "$APP_USER")
app_user_bracket=$(escape_sql_bracket "$APP_USER")
app_pass_lit=$(escape_sql_literal "$APP_PASS")

server="$DB_ENDPOINT"
if echo "$server" | grep -q ","; then
  :
elif echo "$server" | grep -q ":"; then
  host=$(echo "$server" | cut -d: -f1)
  port=$(echo "$server" | cut -d: -f2)
  server="$host,$port"
else
  port="$DB_PORT"
  if [ -z "$port" ]; then port="1433"; fi
  server="$server,$port"
fi

log "Waiting for SQL Server to accept connections..."
max_attempts="$DB_INIT_MAX_ATTEMPTS"
if [ -z "$max_attempts" ]; then max_attempts="30"; fi
sleep_seconds="$DB_INIT_SLEEP_SECONDS"
if [ -z "$sleep_seconds" ]; then sleep_seconds="10"; fi
attempt=1
while true; do
  if sqlcmd -S "$server" -U "$MASTER_USER" -P "$MASTER_PASS" -d master -Q "SELECT 1" -b -C -l 15 >/dev/null 2>&1; then
    break
  fi
  if [ "$attempt" -ge "$max_attempts" ]; then
    log "SQL Server did not become ready after $max_attempts attempts."
    exit 1
  fi
  log "SQL Server not ready yet (attempt $attempt/$max_attempts); sleeping $sleep_seconds s..."
  attempt=$((attempt + 1))
  sleep "$sleep_seconds"
done

cat > /tmp/db-init.sql <<SQL
SET NOCOUNT ON;
IF DB_ID(N'$db_lit') IS NULL
BEGIN
  CREATE DATABASE [$db_bracket];
END
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$app_user_lit')
BEGIN
  CREATE LOGIN [$app_user_bracket] WITH PASSWORD = N'$app_pass_lit';
END
ELSE
BEGIN
  ALTER LOGIN [$app_user_bracket] WITH PASSWORD = N'$app_pass_lit';
END
GO
USE [$db_bracket];
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$app_user_lit')
BEGIN
  CREATE USER [$app_user_bracket] FOR LOGIN [$app_user_bracket];
END
GO
IF NOT EXISTS (
  SELECT 1
  FROM sys.database_role_members rm
  JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
  JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id
  WHERE r.name = N'db_owner' AND m.name = N'$app_user_lit'
)
BEGIN
  ALTER ROLE [db_owner] ADD MEMBER [$app_user_bracket];
END
GO
SQL

log "Running DB init against $DB_ENDPOINT (db: $DB_NAME)..."
sqlcmd -S "$server" -U "$MASTER_USER" -P "$MASTER_PASS" -d master -i /tmp/db-init.sql -b -C -l 30
rm -f /tmp/db-init.sql

log "DB init complete."
run "Update kubeconfig" aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$AWS_REGION" --kubeconfig /tmp/kubeconfig
log "Kubeconfig written to /tmp/kubeconfig"
if [ -n "$KUBECONFIG_S3_BUCKET" ] && [ -n "$KUBECONFIG_S3_KEY" ]; then
  run "Upload kubeconfig to S3" aws s3 cp /tmp/kubeconfig "s3://$KUBECONFIG_S3_BUCKET/$KUBECONFIG_S3_KEY"
  log "Kubeconfig uploaded to s3://$KUBECONFIG_S3_BUCKET/$KUBECONFIG_S3_KEY"
else
  log "Skipping kubeconfig upload (bucket/key not set)."
fi

export KUBECONFIG=/tmp/kubeconfig
log "Deploying Traefik (NLB)..."
  cat > /tmp/traefik-values.yaml <<YAML
    providers:
      kubernetesIngress:
        enabled: true
      kubernetesIngressNginx:
        enabled: false

  service:
    type: LoadBalancer
    annotations:
      service.beta.kubernetes.io/aws-load-balancer-type: nlb
      service.beta.kubernetes.io/aws-load-balancer-security-groups: "$TRAEFIK_NLB_SG_ID"
  YAML
run "Add Traefik Helm repo" helm repo add traefik https://traefik.github.io/charts --force-update
run "Update Helm repos" helm repo update
run "Install/Upgrade Traefik" helm upgrade --install traefik traefik/traefik -n traefik --create-namespace -f /tmp/traefik-values.yaml

log "Waiting for Traefik LoadBalancer hostname..."
lb_host=""
start_ts=$(date +%s)
timeout_seconds=1200
while [ -z "$lb_host" ]; do
  lb_host=$(kubectl get svc -n traefik traefik -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)
  if [ -n "$lb_host" ]; then
    break
  fi
  now_ts=$(date +%s)
  if [ $((now_ts - start_ts)) -ge $timeout_seconds ]; then
    log "Timed out waiting for Traefik LoadBalancer hostname."
    exit 1
  fi
  sleep 10
done
log "Traefik NLB DNS: $lb_host"

if [ -n "$ROUTE53_HOSTED_ZONE_ID" ] && [ -n "$ROUTE53_RECORD_NAME" ]; then
  log "Updating Route53 CNAME $ROUTE53_RECORD_NAME -> $lb_host"
  cat > /tmp/route53.json <<JSON
{"Comment":"Profisee Traefik NLB","Changes":[{"Action":"UPSERT","ResourceRecordSet":{"Name":"$ROUTE53_RECORD_NAME","Type":"CNAME","TTL":60,"ResourceRecords":[{"Value":"$lb_host"}]}}]}
JSON
  run "Update Route53 record" aws route53 change-resource-record-sets --hosted-zone-id "$ROUTE53_HOSTED_ZONE_ID" --change-batch file:///tmp/route53.json
else
  log "Route53 details not set; skipping DNS update."
fi

    if [ -n "$PLATFORM_OUTPUTS_S3_BUCKET" ] && [ -n "$PLATFORM_OUTPUTS_S3_KEY" ]; then
      cat > /tmp/platform.json <<JSON
  {"traefik_nlb_dns":"$lb_host","fqdn":"$ROUTE53_RECORD_NAME"}
  JSON
      run "Upload platform outputs" aws s3 cp /tmp/platform.json "s3://$PLATFORM_OUTPUTS_S3_BUCKET/$PLATFORM_OUTPUTS_S3_KEY"
      log "Platform outputs uploaded to s3://$PLATFORM_OUTPUTS_S3_BUCKET/$PLATFORM_OUTPUTS_S3_KEY"
    fi

    if [ "$APP_DEPLOY_ENABLED" = "true" ]; then
      if [ -z "$SETTINGS_S3_BUCKET" ] || [ -z "$SETTINGS_S3_KEY" ]; then
        log "Skipping app deploy (missing SETTINGS_S3_*)."
      else
        run "Download Settings.yaml" aws s3 cp "s3://$SETTINGS_S3_BUCKET/$SETTINGS_S3_KEY" /tmp/Settings.yaml
        run "Add Profisee Helm repo" helm repo add profisee https://profiseeadmin.github.io/kubernetes --force-update
        run "Update Helm repos" helm repo update
        run "Install/Upgrade Profisee app" helm upgrade --install "$APP_RELEASE_NAME" profisee/profisee-platform -n "$APP_NAMESPACE" --create-namespace -f /tmp/Settings.yaml
      fi
    fi
  EOT
  db_init_env = merge(
    {
      AWS_REGION            = var.region
      CLUSTER_NAME          = var.eks.cluster_name
      DB_ENDPOINT           = module.rds_sqlserver.endpoint
      DB_NAME               = var.rds_sqlserver.db_name
      SECRET_RDS_MASTER_ARN = module.rds_sqlserver.master_user_secret_arn
      SETTINGS_S3_BUCKET    = local.settings_bucket_enabled ? local.settings_bucket_name : ""
      SETTINGS_S3_KEY       = local.settings_bucket_enabled ? local.platform_deployer_settings_key : ""
      KUBECONFIG_S3_BUCKET  = local.settings_bucket_enabled ? local.settings_bucket_name : ""
      KUBECONFIG_S3_KEY     = local.settings_bucket_enabled ? local.kubeconfig_s3_key : ""
      PLATFORM_OUTPUTS_S3_BUCKET = local.settings_bucket_enabled ? local.settings_bucket_name : ""
      PLATFORM_OUTPUTS_S3_KEY    = local.settings_bucket_enabled ? local.platform_outputs_s3_key : ""
      ROUTE53_HOSTED_ZONE_ID     = try(var.route53.hosted_zone_id, "")
      ROUTE53_RECORD_NAME        = try(var.route53.record_name, "")
      TRAEFIK_NLB_SG_ID          = aws_security_group.traefik_nlb.id
      APP_DEPLOY_ENABLED         = local.app_deploy_enabled ? "true" : "false"
      APP_RELEASE_NAME           = local.app_deploy_release_name
      APP_NAMESPACE              = local.app_deploy_namespace
    },
    try(var.db_init.environment, {}),
    local.db_init_secret_env
  )
}

resource "aws_ecs_task_definition" "platform_deployer" {
  count = local.platform_deployer_enabled ? 1 : 0

  family                   = "${var.eks.cluster_name}-platform-deployer"
  cpu                      = tostring(try(var.platform_deployer.cpu, 1024))
  memory                   = tostring(try(var.platform_deployer.memory, 2048))
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.platform_deployer_execution[0].arn
  task_role_arn            = aws_iam_role.platform_deployer_task[0].arn

  container_definitions = jsonencode([
    {
      name      = "platform-deployer"
      image     = var.platform_deployer.image_uri
      essential = true
      environment = [
        for k, v in local.platform_deployer_env : {
          name  = k
          value = tostring(v)
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.platform_deployer[0].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "platform"
        }
      }
    }
  ])
}

resource "aws_ecs_task_definition" "db_init" {
  count = local.db_init_enabled ? 1 : 0

  family                   = "${var.eks.cluster_name}-db-init"
  cpu                      = tostring(try(var.db_init.cpu, 512))
  memory                   = tostring(try(var.db_init.memory, 1024))
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.db_init_execution[0].arn
  task_role_arn            = aws_iam_role.db_init_task[0].arn

  container_definitions = jsonencode([
    merge(
      {
        name      = "db-init"
        image     = var.db_init.image_uri
        essential = true
        command   = ["/bin/bash", "-lc", local.db_init_command]
        environment = [
          for k, v in local.db_init_env : {
            name  = k
            value = tostring(v)
          }
        ]
        logConfiguration = {
          logDriver = "awslogs"
          options = {
            awslogs-group         = aws_cloudwatch_log_group.db_init[0].name
            awslogs-region        = var.region
            awslogs-stream-prefix = "db-init"
          }
        }
      },
      local.db_init_acr_secret_arn != null ? {
        repositoryCredentials = {
          credentialsParameter = local.db_init_acr_secret_arn
        }
      } : {}
    )
  ])
}

resource "aws_eks_access_entry" "platform_deployer" {
  count = local.platform_deployer_enabled ? 1 : 0

  cluster_name  = module.eks.cluster_name
  principal_arn = aws_iam_role.platform_deployer_task[0].arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "platform_deployer" {
  count = local.platform_deployer_enabled ? 1 : 0

  cluster_name  = module.eks.cluster_name
  principal_arn = aws_iam_role.platform_deployer_task[0].arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }
}

resource "aws_eks_access_entry" "db_init" {
  count = local.db_init_enabled ? 1 : 0

  cluster_name  = module.eks.cluster_name
  principal_arn = aws_iam_role.db_init_task[0].arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "db_init" {
  count = local.db_init_enabled ? 1 : 0

  cluster_name  = module.eks.cluster_name
  principal_arn = aws_iam_role.db_init_task[0].arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }
}

module "rds_sqlserver" {
  source = "../modules/rds_sqlserver"

  identifier                    = var.rds_sqlserver.identifier
  engine_version                = var.rds_sqlserver.engine_version
  instance_class                = var.rds_sqlserver.instance_class
  allocated_storage             = var.rds_sqlserver.allocated_storage
  max_allocated_storage         = var.rds_sqlserver.max_allocated_storage
  storage_type                  = var.rds_sqlserver.storage_type
  iops                          = var.rds_sqlserver.iops
  storage_encrypted             = var.rds_sqlserver.storage_encrypted
  kms_key_arn                   = var.rds_sqlserver.kms_key_arn
  master_username               = var.rds_sqlserver.master_username
  manage_master_user_password   = var.rds_sqlserver.manage_master_user_password
  master_user_secret_kms_key_id = var.rds_sqlserver.master_user_secret_kms_key_id
  vpc_id                        = module.vpc.vpc_id
  subnet_ids                    = module.vpc.private_subnet_ids
  allowed_security_group_ids    = concat(
    var.rds_sqlserver.allowed_security_group_ids,
    local.jumpbox_enabled ? [module.jumpbox_windows[0].security_group_id] : [],
    local.platform_deployer_enabled ? [aws_security_group.platform_deployer[0].id] : [],
    local.db_init_enabled ? [aws_security_group.db_init[0].id] : []
  )
  backup_retention_days         = var.rds_sqlserver.backup_retention_days
  multi_az                      = var.rds_sqlserver.multi_az
  publicly_accessible           = var.rds_sqlserver.publicly_accessible
  deletion_protection           = var.rds_sqlserver.deletion_protection
  tags                          = var.rds_sqlserver.tags
}

module "kms" {
  source = "../modules/kms"

  keys = var.kms.keys
  tags = var.kms.tags
}

module "secrets" {
  source = "../modules/secrets"

  secrets = var.secrets.secrets
  tags    = var.secrets.tags
}

module "acm_use1" {
  source    = "../modules/acm_use1"
  providers = { aws = aws.use1 }

  domain_name             = var.acm.domain_name
  subject_alternative_names = var.acm.subject_alternative_names
  hosted_zone_id          = var.acm.hosted_zone_id
  validation_method       = var.acm.validation_method
  create_route53_records  = var.acm.create_route53_records
  tags                    = var.acm.tags
}

module "cloudfront" {
  count  = var.cloudfront.enabled ? 1 : 0
  source = "../modules/cloudfront"

  enabled                   = var.cloudfront.enabled
  aliases                   = var.cloudfront.aliases
  acm_certificate_arn       = module.acm_use1.certificate_arn
  origin_domain_name        = var.cloudfront.origin_domain_name
  origin_id                 = var.cloudfront.origin_id
  origin_protocol_policy    = var.cloudfront.origin_protocol_policy
  origin_ssl_protocols      = var.cloudfront.origin_ssl_protocols
  origin_read_timeout       = var.cloudfront.origin_read_timeout
  origin_keepalive_timeout  = var.cloudfront.origin_keepalive_timeout
  origin_custom_headers      = var.cloudfront.origin_custom_headers
  price_class               = var.cloudfront.price_class
  web_acl_id                = var.cloudfront.web_acl_id
  enable_logging            = var.cloudfront.enable_logging
  logging_bucket            = var.cloudfront.logging_bucket
  tags                      = var.cloudfront.tags
}

module "route53" {
  count  = var.cloudfront.enabled && var.route53.enabled ? 1 : 0
  source = "../modules/route53"

  hosted_zone_id         = var.route53.hosted_zone_id
  record_name            = var.route53.record_name
  record_type            = var.route53.record_type
  alias_name             = module.cloudfront[0].distribution_domain_name
  alias_zone_id          = module.cloudfront[0].hosted_zone_id
  evaluate_target_health = var.route53.evaluate_target_health
}

locals {
  jumpbox_secret_arns = distinct([
    for arn in concat(
      length(try(var.platform_deployer.secret_arns, {})) > 0 ? values(var.platform_deployer.secret_arns) : [],
      try(var.rds_sqlserver.manage_master_user_password, true) ? [module.rds_sqlserver.master_user_secret_arn] : []
    ) : arn if arn != null && arn != ""
  ])
  jumpbox_secrets_enabled = local.jumpbox_enabled && (
    length(try(var.platform_deployer.secret_arns, {})) > 0 ||
    try(var.rds_sqlserver.manage_master_user_password, true)
  )
  jumpbox_settings_enabled = local.jumpbox_enabled && local.settings_bucket_enabled
  jumpbox_route53_enabled = local.jumpbox_enabled && try(var.route53.hosted_zone_id, "") != ""
}

data "aws_iam_policy_document" "jumpbox_secrets" {
  count = local.jumpbox_secrets_enabled ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue"
    ]
    resources = local.jumpbox_secret_arns
  }

  dynamic "statement" {
    for_each = try(var.rds_sqlserver.master_user_secret_kms_key_id, null) != null ? [var.rds_sqlserver.master_user_secret_kms_key_id] : []
    content {
      effect = "Allow"
      actions = ["kms:Decrypt"]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_policy" "jumpbox_secrets" {
  count = length(data.aws_iam_policy_document.jumpbox_secrets) > 0 ? 1 : 0

  name   = "${var.eks.cluster_name}-jumpbox-secrets"
  policy = data.aws_iam_policy_document.jumpbox_secrets[0].json
  tags   = local.jumpbox_tags
}

data "aws_iam_policy_document" "jumpbox_settings" {
  count = local.jumpbox_settings_enabled ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "s3:ListBucket"
    ]
    resources = [aws_s3_bucket.settings[0].arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["settings/*", "kubeconfig/*"]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion"
    ]
    resources = [
      "${aws_s3_bucket.settings[0].arn}/settings/*",
      "${aws_s3_bucket.settings[0].arn}/kubeconfig/*"
    ]
  }

  dynamic "statement" {
    for_each = try(var.settings_bucket.kms_key_arn, null) != null ? [var.settings_bucket.kms_key_arn] : []
    content {
      effect = "Allow"
      actions = ["kms:Decrypt"]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_policy" "jumpbox_settings" {
  count = length(data.aws_iam_policy_document.jumpbox_settings) > 0 ? 1 : 0

  name   = "${var.eks.cluster_name}-jumpbox-settings"
  policy = data.aws_iam_policy_document.jumpbox_settings[0].json
  tags   = local.jumpbox_tags
}

data "aws_iam_policy_document" "jumpbox_route53" {
  count = local.jumpbox_route53_enabled ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "route53:GetHostedZone",
      "route53:ListResourceRecordSets",
      "route53:ChangeResourceRecordSets"
    ]
    resources = ["arn:aws:route53:::hostedzone/${var.route53.hosted_zone_id}"]
  }
}

resource "aws_iam_policy" "jumpbox_route53" {
  count = length(data.aws_iam_policy_document.jumpbox_route53) > 0 ? 1 : 0

  name   = "${var.eks.cluster_name}-jumpbox-route53"
  policy = data.aws_iam_policy_document.jumpbox_route53[0].json
  tags   = local.jumpbox_tags
}

locals {
  jumpbox_policy_arns = concat(
    var.jumpbox.iam_policy_arns,
    length(aws_iam_policy.jumpbox_secrets) > 0 ? [aws_iam_policy.jumpbox_secrets[0].arn] : [],
    length(aws_iam_policy.jumpbox_settings) > 0 ? [aws_iam_policy.jumpbox_settings[0].arn] : [],
    length(aws_iam_policy.jumpbox_route53) > 0 ? [aws_iam_policy.jumpbox_route53[0].arn] : []
  )
}

module "jumpbox_windows" {
  count  = local.jumpbox_enabled ? 1 : 0
  source = "../modules/jumpbox_windows"

  name                 = local.jumpbox_name
  vpc_id               = module.vpc.vpc_id
  subnet_id            = local.jumpbox_subnet_id
  instance_type        = var.jumpbox.instance_type
  ami_id               = var.jumpbox.ami_id
  key_name             = var.jumpbox.key_name
  iam_policy_arns      = local.jumpbox_policy_arns
  assume_role_arn      = var.jumpbox.assume_role_arn
  associate_public_ip  = var.jumpbox.associate_public_ip
  root_volume_size_gb  = var.jumpbox.root_volume_size_gb
  enable_rdp_ingress   = var.jumpbox.enable_rdp_ingress
  allowed_rdp_cidrs    = var.jumpbox.allowed_rdp_cidrs
  user_data            = var.jumpbox.user_data
  region               = var.region
  settings_bucket_name = local.settings_bucket_enabled ? local.settings_bucket_name : ""
  kubeconfig_s3_key    = local.kubeconfig_s3_key
  tags                 = local.jumpbox_tags
}

resource "aws_ebs_volume" "app_fileshare" {
  count = local.app_ebs_enabled ? 1 : 0

  availability_zone = local.app_ebs_az
  size              = try(var.app_ebs.size_gb, 5)
  type              = try(var.app_ebs.type, "gp3")
  iops              = try(var.app_ebs.iops, null)
  throughput        = try(var.app_ebs.throughput, null)
  encrypted         = try(var.app_ebs.encrypted, true)
  kms_key_id         = try(var.app_ebs.kms_key_id, null)

  tags = merge(
    local.app_ebs_tags,
    { Name = "${var.eks.cluster_name}-fileshare" }
  )
}

locals {
  app_ebs_volume_id = local.app_ebs_enabled ? aws_ebs_volume.app_fileshare[0].id : var.app_ebs_volume_id
}

resource "aws_security_group_rule" "jumpbox_to_eks_api" {
  count = local.jumpbox_enabled ? 1 : 0

  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = module.eks.cluster_security_group_id
  source_security_group_id = module.jumpbox_windows[0].security_group_id
  description              = "Allow jumpbox access to EKS API"
}

resource "aws_security_group_rule" "db_init_to_eks_api" {
  count = local.db_init_enabled ? 1 : 0

  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = module.eks.cluster_security_group_id
  source_security_group_id = aws_security_group.db_init[0].id
  description              = "Allow db-init Fargate access to EKS API"
}

module "outputs_contract" {
  source = "../modules/outputs_contract"

  outputs = {
    region                     = var.region
    use1_region                = var.use1_region
    app_ebs_volume_id          = local.app_ebs_volume_id
    settings_bucket_name       = local.settings_bucket_enabled ? aws_s3_bucket.settings[0].bucket : null
    settings_bucket_arn        = local.settings_bucket_enabled ? aws_s3_bucket.settings[0].arn : null
    settings_s3_key            = local.platform_deployer_settings_key
    settings_s3_uri            = local.platform_deployer_settings_uri
    kubeconfig_s3_key          = local.kubeconfig_s3_key
    kubeconfig_s3_uri          = local.kubeconfig_s3_uri
    platform_outputs_s3_key    = local.platform_outputs_s3_key
    platform_outputs_s3_uri    = local.platform_outputs_s3_uri
    platform_deployer_cluster_arn         = local.platform_deployer_enabled ? aws_ecs_cluster.platform_deployer[0].arn : null
    platform_deployer_task_definition_arn = local.platform_deployer_enabled ? aws_ecs_task_definition.platform_deployer[0].arn : null
    platform_deployer_task_role_arn       = local.platform_deployer_enabled ? aws_iam_role.platform_deployer_task[0].arn : null
    platform_deployer_security_group_id   = local.platform_deployer_enabled ? aws_security_group.platform_deployer[0].id : null
    db_init_cluster_arn         = local.db_init_enabled ? aws_ecs_cluster.db_init[0].arn : null
    db_init_task_definition_arn = local.db_init_enabled ? aws_ecs_task_definition.db_init[0].arn : null
    db_init_task_role_arn       = local.db_init_enabled ? aws_iam_role.db_init_task[0].arn : null
    db_init_security_group_id   = local.db_init_enabled ? aws_security_group.db_init[0].id : null
    vpc_id                     = module.vpc.vpc_id
    public_subnet_ids          = module.vpc.public_subnet_ids
    private_subnet_ids         = module.vpc.private_subnet_ids
    cluster_name               = module.eks.cluster_name
    cluster_endpoint           = module.eks.cluster_endpoint
    cluster_ca_data            = module.eks.cluster_ca_data
    rds_endpoint               = module.rds_sqlserver.endpoint
    rds_port                   = module.rds_sqlserver.port
    rds_master_user_secret_arn = module.rds_sqlserver.master_user_secret_arn
    cloudfront_id              = var.cloudfront.enabled ? module.cloudfront[0].distribution_id : null
    cloudfront_domain_name     = var.cloudfront.enabled ? module.cloudfront[0].distribution_domain_name : null
    cloudfront_hosted_zone_id  = var.cloudfront.enabled ? module.cloudfront[0].hosted_zone_id : null
    route53_record_fqdn        = var.cloudfront.enabled && var.route53.enabled ? module.route53[0].record_fqdn : null
    acm_certificate_arn        = module.acm_use1.certificate_arn
    jumpbox_instance_id        = local.jumpbox_enabled ? module.jumpbox_windows[0].instance_id : null
    jumpbox_private_ip         = local.jumpbox_enabled ? module.jumpbox_windows[0].private_ip : null
    jumpbox_public_ip          = local.jumpbox_enabled ? module.jumpbox_windows[0].public_ip : null
    jumpbox_security_group_id  = local.jumpbox_enabled ? module.jumpbox_windows[0].security_group_id : null
    jumpbox_role_arn           = local.jumpbox_enabled ? module.jumpbox_windows[0].iam_role_arn : null
  }
}

