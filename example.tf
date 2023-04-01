provider "aws" {
  region = "us-west-2"

  # These are not real credentials, just an example
  aws_access_key_id     = "AKIAIOSFODNN7EXAMPLE"
  aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_s3_bucket" "example_bucket" {
  bucket = "my-example-bucket"
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "example_public_access_block" {
  bucket = aws_s3_bucket.example_bucket.id

  block_public_acls   = true
  block_public_policy = true
}
