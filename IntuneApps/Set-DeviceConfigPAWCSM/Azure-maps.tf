
# copy file to a folder somewhere on your machine
# Once terraform is installed and in the path
# run az login to authenticate using your current creds
# then change any values below 
# run terrform init
# run terraform plan 
# once you are happy run terraform apply . This will create the resources for you. terrafrom destroy will remove them


# Local subscription: 
provider "azurerm" {
  version = ">= 2.0.0"

  features {}
}

#/*
# This will create a new resource group
resource "azurerm_resource_group" "this" {
  name     = "example-resources"  # < Change  name of the rg here
  location = "West Europe"  # < Change location here
}
#*/

resource "azurerm_maps_account" "this" {
  name                = "example-maps-account"
  resource_group_name = azurerm_resource_group.this.name  # < if you want to use a prexisting resource group just provide the name in "" instead and remove the # from the /* and */
  sku_name            = "S0"
}