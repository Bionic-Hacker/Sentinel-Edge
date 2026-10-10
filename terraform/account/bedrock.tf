# The local API's Bedrock identity (ADR-0024, C-AI-07). This account has no IAM users or access
# keys: people sign in with `aws login`, and that session can do everything. So the local API
# never gets that session; `make bedrock-credentials` assumes this role instead, which may invoke
# one model and nothing else. In Phase 4 the ECS task role takes over the same single permission.

data "aws_iam_policy_document" "local_bedrock_assume" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }
}

data "aws_iam_policy_document" "local_bedrock" {
  statement {
    sid       = "InvokeOneModel"
    actions   = ["bedrock:InvokeModel"]
    resources = ["arn:aws:bedrock:${var.region}::foundation-model/${var.bedrock_model_id}"]
  }
}

resource "aws_iam_role" "local_bedrock" {
  name                 = "${var.project}-local-bedrock"
  description          = "Assumed by make bedrock-credentials: bedrock:InvokeModel on one model, nothing else."
  assume_role_policy   = data.aws_iam_policy_document.local_bedrock_assume.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "local_bedrock" {
  name   = "invoke-one-model"
  role   = aws_iam_role.local_bedrock.id
  policy = data.aws_iam_policy_document.local_bedrock.json
}
