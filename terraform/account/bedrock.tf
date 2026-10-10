# The local API's Bedrock identity (ADR-0024, C-AI-07). Nova Micro is offered in us-east-2 only
# through the US cross-region inference profile (us.amazon.nova-micro-v1:0, checked 2026-10-09),
# so the role may invoke that profile, and the model itself only when the call comes through it. This account has no IAM users or access
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

locals {
  inference_profile_arn = "arn:aws:bedrock:${var.region}:${var.account_id}:inference-profile/us.${var.bedrock_model_id}"
}

data "aws_iam_policy_document" "local_bedrock" {
  statement {
    sid       = "InvokeThroughTheUsProfile"
    actions   = ["bedrock:InvokeModel"]
    resources = [local.inference_profile_arn]
  }

  # The profile routes each call to the model in one of these Regions; the permission applies
  # only to calls made through this profile, never to the model directly.
  statement {
    sid       = "TheModelOnlyThroughThatProfile"
    actions   = ["bedrock:InvokeModel"]
    resources = [for r in var.bedrock_profile_regions : "arn:aws:bedrock:${r}::foundation-model/${var.bedrock_model_id}"]

    condition {
      test     = "StringEquals"
      variable = "bedrock:InferenceProfileArn"
      values   = [local.inference_profile_arn]
    }
  }
}

resource "aws_iam_role" "local_bedrock" {
  name                 = "${var.project}-local-bedrock"
  description          = "Assumed by make bedrock-credentials: invoke one model through its US profile, nothing else."
  assume_role_policy   = data.aws_iam_policy_document.local_bedrock_assume.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "local_bedrock" {
  name   = "invoke-one-model"
  role   = aws_iam_role.local_bedrock.id
  policy = data.aws_iam_policy_document.local_bedrock.json
}
