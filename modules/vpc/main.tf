data "aws_ec2_transit_gateway_attachment" "bayer_connected_vpc" {
  count = var.bayer_connect_managed ? 1 : 0
  filter {
    name   = "resource-owner-id"
    values = ["762052912533"]
  }
}

resource "aws_vpc" "main" {
  cidr_block           = var.cidr_vpc
  enable_dns_hostnames = true

  tags = {
    Name                = "main"
    BayerConnectManaged = tostring(var.bayer_connect_managed)
  }
}

resource "aws_flow_log" "main" {
  log_destination      = var.bucket_logs_arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.main.id

  tags = {
    BayerConnectManaged = tostring(var.bayer_connect_managed)
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_eip" "gw_a" {
  vpc      = true
}

resource "aws_eip" "gw_b" {
  vpc      = true
}

resource "aws_nat_gateway" "gw_a" {
  allocation_id = aws_eip.gw_a.id
  subnet_id     = aws_subnet.public_a.id
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "gw_b" {
  allocation_id = aws_eip.gw_b.id
  subnet_id     = aws_subnet.public_b.id
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_default_route_table" "main" {
  default_route_table_id = aws_vpc.main.default_route_table_id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "private_a" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.gw_a.id
  }
  dynamic "route" {
    for_each = var.bayer_connect_managed ? [1] : []
    content {
      cidr_block         = "10.0.0.0/8"
      transit_gateway_id = data.aws_ec2_transit_gateway_attachment.bayer_connected_vpc[0].transit_gateway_id
    }
  }
  dynamic "route" {
    for_each = var.bayer_connect_managed ? [1] : []
    content {
      cidr_block         = "164.59.240.0/21"
      transit_gateway_id = data.aws_ec2_transit_gateway_attachment.bayer_connected_vpc[0].transit_gateway_id
    }
  }
  dynamic "route" {
    for_each = var.bayer_connect_managed ? [1] : []
    content {
      cidr_block         = "172.16.0.0/12"
      transit_gateway_id = data.aws_ec2_transit_gateway_attachment.bayer_connected_vpc[0].transit_gateway_id
    }
  }
  depends_on = [aws_nat_gateway.gw_a]

  tags = {
    BayerConnectManaged = tostring(var.bayer_connect_managed)
  }
}

resource "aws_route_table" "private_b" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.gw_b.id
  }
  dynamic "route" {
    for_each = var.bayer_connect_managed ? [1] : []
    content {
      cidr_block         = "10.0.0.0/8"
      transit_gateway_id = data.aws_ec2_transit_gateway_attachment.bayer_connected_vpc[0].transit_gateway_id
    }
  }
  dynamic "route" {
    for_each = var.bayer_connect_managed ? [1] : []
    content {
      cidr_block         = "164.59.240.0/21"
      transit_gateway_id = data.aws_ec2_transit_gateway_attachment.bayer_connected_vpc[0].transit_gateway_id
    }
  }
  dynamic "route" {
    for_each = var.bayer_connect_managed ? [1] : []
    content {
      cidr_block         = "172.16.0.0/12"
      transit_gateway_id = data.aws_ec2_transit_gateway_attachment.bayer_connected_vpc[0].transit_gateway_id
    }
  }
  depends_on = [aws_nat_gateway.gw_b]

  tags = {
    BayerConnectManaged = tostring(var.bayer_connect_managed)
  }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.cidr_subnet_public_a
  availability_zone       = "eu-central-1a"
  depends_on              = [aws_internet_gateway.main]
  map_public_ip_on_launch = false

  tags = {
    Name = "public-euc1a"
  }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.cidr_subnet_public_b
  availability_zone       = "eu-central-1b"
  depends_on              = [aws_internet_gateway.main]
  map_public_ip_on_launch = false

  tags = {
    Name = "public-euc1b"
  }
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.cidr_subnet_private_a
  availability_zone       = "eu-central-1a"
  depends_on              = [aws_nat_gateway.gw_a]
  map_public_ip_on_launch = false

  tags = {
    Name                = "private-euc1a",
    BayerConnectManaged = tostring(var.bayer_connect_managed)
  }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private_a.id
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.cidr_subnet_private_b
  availability_zone       = "eu-central-1b"
  depends_on              = [aws_nat_gateway.gw_b]
  map_public_ip_on_launch = false

  tags = {
    Name                = "private-euc1b",
    BayerConnectManaged = tostring(var.bayer_connect_managed)
  }
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private_b.id
}
