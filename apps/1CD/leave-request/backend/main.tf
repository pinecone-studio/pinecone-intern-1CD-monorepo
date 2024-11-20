terraform {
  required_providers {
    vercel = {
      source  = "vercel/vercel"
      version = "~> 0.3"
    }
  }
}

resource "vercel_project" "leave-request-backend-prod" {
  name             = "intern-1cd-leave-request-backend-prod"
  build_command    = "nx build --skip-nx-cache leave-request-backend"
  output_directory = "./dist/apps/1CD/leave-request/backend/.next"
  framework        = "nextjs"
  team_id          = "team_0ASDilhqwPl5fll9OnzqDM30"
}
resource "vercel_project" "leave-request-backend-testing" {
  name             = "intern-1cd-leave-request-backend-testing"
  build_command    = "nx build --skip-nx-cache leave-request-backend"
  output_directory = "./dist/apps/1CD/leave-request/backend/.next"
  framework        = "nextjs"
  team_id          = "team_0ASDilhqwPl5fll9OnzqDM30"
}

variable "VERCEL_TOKEN" {
  type        = string
  description = "Optionally say something about this variable"
}

provider "vercel" {
  # Or omit this for the api_token to be read
  # from the VERCEL_API_TOKEN environment variable
  api_token = var.VERCEL_TOKEN

  # Optional default team for all resources
  team = "team_0ASDilhqwPl5fll9OnzqDM30"
}