<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
        <title>&&TITLE&&</title>

    <!-- Bootstrap core CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.10.20/css/jquery.dataTables.min.css" crossorigin="anonymous">

    <style>
      .bd-placeholder-img {
        font-size: 1.125rem;
        text-anchor: middle;
        -webkit-user-select: none;
        -moz-user-select: none;
        -ms-user-select: none;
        user-select: none;
      }

      @media (min-width: 768px) {
        .bd-placeholder-img-lg {
          font-size: 3.5rem;
        }
      }
    </style>
    <!-- Custom styles for this template -->
        <link href="https://aquademo.s3-us-west-2.amazonaws.com/dashboard.css" rel="stylesheet">
  </head>
  <body>
    <nav class="navbar navbar-dark fixed-top bg-dark flex-md-nowrap p-0 shadow">
      <a class="navbar-brand col-sm-3 col-md-2 mr-0" href="#">&&IMAGE&&</a>
    </nav>

<div class="container-fluid">
  <div class="row">
    <nav class="col-md-2 d-none d-md-block bg-light sidebar">
      <div class="sidebar-sticky">
        <ul class="nav flex-column">
          <li class="nav-item">
            <a class="nav-link" href="#risk">
              <span data-feather="home"></span>
              Risk 
            </a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="#vulnerabilities">
              <span data-feather="file"></span>
              Vulnerabilities
            </a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="#sensitive">
              <span data-feather="shopping-cart"></span>
              Sensitive
            </a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="#malware">
              <span data-feather="users"></span>
              Malware
            </a>
          </li>
        </ul>
      </div>
    </nav>

    <main role="main" class="col-md-9 ml-sm-auto col-lg-10 px-4">

      <h2>Risk</h2>
      <div class="table-responsive">
        <table class="table table-striped table-sm" id="risk">
          <thead>
            <tr>
              <th>Total Vulns</th>
              <th>High Vulns</th>
              <th>Medium Vulns</th>
              <th>Low Vulns</th>
              <th>Negligible Vulns</th>
              <th>Malware Count</th>
              <th>Sensitive Count</th>
              <th>Whitelisted</th>
              <th>Blacklisted</th>
              <th>Scan Date</th>
            </tr>
          </thead>
          <tbody>