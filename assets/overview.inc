<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
	<link rel="stylesheet" href="https://community-aqua-reports.s3.amazonaws.com/report.css">
    <link rel="stylesheet" href="https://community-aqua-reports.s3.amazonaws.com/overview.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.10.20/css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/buttons/1.6.0/css/buttons.dataTables.min.css">

    <script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
	<script src="https://cdn.datatables.net/1.10.20/js/jquery.dataTables.min.js"></script>
    <!-- <script src="https://cdn.datatables.net/buttons/1.6.0/js/dataTables.buttons.min.js"></script> -->

        <!-- Flot -->
    <script src="https://community-aqua-reports.s3.amazonaws.com/flot/jquery.flot.js"></script>
    <script src="https://community-aqua-reports.s3.amazonaws.com/flot/jquery.flot.tooltip.min.js"></script>
    <script src="https://community-aqua-reports.s3.amazonaws.com/flot/jquery.flot.spline.js"></script>
    <script src="https://community-aqua-reports.s3.amazonaws.com/flot/jquery.flot.resize.js"></script>
    <script src="https://community-aqua-reports.s3.amazonaws.com/flot/jquery.flot.pie.js"></script>
    <script src="https://community-aqua-reports.s3.amazonaws.com/flot/jquery.flot.symbol.js"></script>
    <script src="https://community-aqua-reports.s3.amazonaws.com/flot/curvedLines.js"></script>
    
    <title>Executive Overview - Aqua CSP</title>
</head>
<body>
<div class="aqua-container">
<header class="header">
    <svg class="logo" viewBox="0 0 490.42 176" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <style>.cls-1 {
                fill: #f1df36;
            }
            .cls-2 {
                fill: #faaf42;
            }
            .cls-3 {
                fill: #9ad7ec;
            }
            .cls-4 {
                fill: #08b1d5;
            }
            .cls-5 {
                fill: #f69421;
            }
            .cls-6 {
                fill: #1180c4;
            }
            .cls-7 {
                fill: #fff;
            }
            .cls-8 {
                fill: none;
                stroke: #f69421;
                stroke-miterlimit: 10;
                stroke-width: 22px;
            }</style>
        </defs>
        <title>aqua_logo_</title>
        <polygon class="cls-1" points="85.58 20 50.78 54 120.38 54 120.38 20"/>
        <polygon class="cls-2" points="120.38 122 155.18 88 155.18 54 120.38 54"/>
        <polygon class="cls-3" points="50.78 122 50.78 156 85.58 156 120.38 122"/>
        <polygon class="cls-4" points="15.98 88 15.98 122 50.78 122 50.78 54"/>
        <rect class="cls-5" x="120.38" y="20" width="34.8" height="34"/>
        <rect class="cls-6" x="15.98" y="122" width="34.8" height="34"/>
        <path class="cls-7" d="M239.94,51.45A25.86,25.86,0,0,0,230.15,47a59.53,59.53,0,0,0-12.93-1.21A70,70,0,0,0,204.48,47c-4.24.79-7.54,1.52-9.82,2.18l-1.08.31v15h2.52l0.28-.12a65.57,65.57,0,0,1,11.17-3.59,45.5,45.5,0,0,1,9.61-1.23,47.4,47.4,0,0,1,6.74.47A12.9,12.9,0,0,1,229,61.79a8.09,8.09,0,0,1,3.07,3.44,14.35,14.35,0,0,1,1.14,6.25v0.92c-5.91.35-11.49,0.86-16.62,1.52a51.69,51.69,0,0,0-14.84,4,23.27,23.27,0,0,0-10.73,9,26,26,0,0,0-3.4,13.6,26.31,26.31,0,0,0,1.86,9.81,23.78,23.78,0,0,0,5,7.87,23.46,23.46,0,0,0,16.65,6.87,31.87,31.87,0,0,0,8.91-1,38,38,0,0,0,6.5-2.69,29.78,29.78,0,0,0,5.1-3.32l1.56-1.23v6.2H248.4V71.94a32.05,32.05,0,0,0-2.06-12.13A19.67,19.67,0,0,0,239.94,51.45Zm-6.68,33.76V103a44,44,0,0,1-8,5.5,20.44,20.44,0,0,1-9.75,2.32c-4.1,0-7.21-.94-9.25-2.79s-3-4.56-3-8.3c0-3.29.89-5.75,2.73-7.53A18.22,18.22,0,0,1,213.43,88a58.31,58.31,0,0,1,10.47-1.86C227.49,85.76,230.62,85.46,233.25,85.21Z"/>
        <path class="cls-7" d="M306.7,49.86a40.8,40.8,0,0,0-6.95-3,33.78,33.78,0,0,0-10.13-1.37,28.89,28.89,0,0,0-12.26,2.74A29.53,29.53,0,0,0,267.26,56a39,39,0,0,0-7.07,12.52,50.69,50.69,0,0,0-2.65,17c0,12.05,2.57,21.63,7.63,28.46a24.78,24.78,0,0,0,20.88,10.51,29.1,29.1,0,0,0,11.84-2.37,37.47,37.47,0,0,0,8.28-5.21v32.91h15.21V47.52h-14.1Zm-7.63,10.48A39.15,39.15,0,0,1,306.18,63v39.67a35,35,0,0,1-8.08,5.1,22.6,22.6,0,0,1-9.38,2.08c-5.33,0-9.14-2-11.64-6.13-2.61-4.31-3.94-10.63-3.94-18.8,0-8.33,1.65-14.76,4.9-19.1s7.64-6.35,13.61-6.35A30.68,30.68,0,0,1,299.07,60.35Z"/>
        <path class="cls-7" d="M380.35,102.49a42.28,42.28,0,0,1-8.46,5.58,20,20,0,0,1-8.88,2.38,15.39,15.39,0,0,1-6.69-1.14,7.82,7.82,0,0,1-3.41-3.45,17.3,17.3,0,0,1-1.75-6.13,88,88,0,0,1-.41-9.41V47.52H335.54V96.1a41.14,41.14,0,0,0,1.8,12.95,24.82,24.82,0,0,0,5.16,9,20.29,20.29,0,0,0,7.89,5.32,27,27,0,0,0,9.45,1.65,26.25,26.25,0,0,0,12-2.73,50.21,50.21,0,0,0,8.54-5.63v6.34h15.21V47.52H380.35v55Z"/>
        <path class="cls-7" d="M463.82,59.81a19.67,19.67,0,0,0-6.4-8.36A25.86,25.86,0,0,0,447.64,47a59.53,59.53,0,0,0-12.93-1.21A70,70,0,0,0,422,47c-4.24.79-7.54,1.52-9.82,2.18l-1.08.31v15h2.52l0.28-.12A65.57,65.57,0,0,1,425,60.78a45.5,45.5,0,0,1,9.61-1.23,47.4,47.4,0,0,1,6.74.47,12.9,12.9,0,0,1,5.15,1.78,8.09,8.09,0,0,1,3.07,3.44,14.35,14.35,0,0,1,1.14,6.25v0.92c-5.91.35-11.49,0.86-16.62,1.52a51.69,51.69,0,0,0-14.84,4,23.27,23.27,0,0,0-10.73,9,26,26,0,0,0-3.4,13.6,26.31,26.31,0,0,0,1.86,9.81,23.78,23.78,0,0,0,5,7.87,23.46,23.46,0,0,0,16.65,6.87,31.87,31.87,0,0,0,8.91-1,38,38,0,0,0,6.5-2.69,29.78,29.78,0,0,0,5.1-3.32l1.56-1.23v6.2h15.14V71.94A32.05,32.05,0,0,0,463.82,59.81Zm-13.08,25.4V103a44,44,0,0,1-8,5.5,20.44,20.44,0,0,1-9.75,2.32c-4.1,0-7.21-.94-9.25-2.79s-3-4.56-3-8.3c0-3.29.89-5.75,2.73-7.53A18.22,18.22,0,0,1,430.92,88a58.31,58.31,0,0,1,10.47-1.86C445,85.76,448.11,85.46,450.74,85.21Z"/>
        <rect class="cls-8" x="-604.42" y="-703.27" width="1676" height="1646"/>
    </svg>
</header>
<main class="content">
    <div class="row" style="padding-top: 5px; padding-left: 20px; padding-right: 20px">
        <div class="col">
            <div class="el-card flex1 mr-m chart-box is-always-shadow">
                <div class="el-card__header">
                    <div class="flex space-between center-v">
                        <h5> Containers </h5>
                    </div>
                </div>
                <div class="el-card__body">
                    <div>
                        <div class="flex border-bottom mb-s">
                            <div class="flex-col center-v center-h flex1 pb-s border-right">
                                <h3 class="mb-xs text-primary">&&RUNNING&&</h3>
                                <span>Running</span>
                            </div>
                            <div class="flex-col center-v center-h flex1 pb-s">
                                <h3 class="mb-xs text-warning">&&UNREGISTERED&&</h3>
                                <span>Unregistered</span>
                            </div>
                        </div> <!-- end of first row (flex border-bottom mb-s) -->
                        <div class="flex border-bottom mb-s">
                            <div class="flex-col center-v center-h flex1 pb-s border-right">
                                <h3 class="mb-xs text-alert">&&CONTAINERSCRITICAL&&</h3>
                                <span>Critical</span>
                            </div>
                            <div class="flex-col center-v center-h flex1 pb-s">
                                <h3 class="mb-xs text-danger">&&CONTAINERSHIGH&&</h3>
                                <span>High</span>
                            </div>
                        </div> <!-- end of second row (flex border-bottom mb-s) -->    
                    </div>  
                </div>
                <!-- <div id="flot-containers" style="width:100%;height:300px;"></div> -->
            </div>
        </div>

        <div class="col">
            <div class="el-card flex1 mr-m chart-box is-always-shadow">
                <div class="el-card__header">
                    <div class="flex space-between center-v">
                        <h5> Images </h5>
                    </div>
                </div>
                <div class="el-card__body">
                    <div>
                        <div class="flex border-bottom mb-s">
                            <div class="flex-col center-v center-h flex1 pb-s border-right">
                                <h3 class="mb-xs text-primary">&&IMAGESSCANNED&&</h3>
                                <span>Registered</span>
                            </div>
                            <div class="flex-col center-v center-h flex1 pb-s">
                                <h3 class="mb-xs text-success">&&IMAGESOK&&</h3>
                                <span>Ok</span>
                            </div>
                        </div> <!-- end of first row (flex border-bottom mb-s) -->
                        <div class="flex border-bottom mb-s">
                            <div class="flex-col center-v center-h flex1 pb-s border-right">
                                <h3 class="mb-xs text-alert">&&IMAGESCRITICAL&&</h3>
                                <span>Critical</span>
                            </div>
                            <div class="flex-col center-v center-h flex1 pb-s">
                                <h3 class="mb-xs text-danger">&&IMAGESHIGH&&</h3>
                                <span>High</span>
                            </div>
                        </div> <!-- end of second row (flex border-bottom mb-s) -->    
                    </div>  
                </div>
                <!-- <div id="flot-images" style="width:100%;height:300px;"></div> -->
            </div>
        </div>

        <div class="col">
            <div class="el-card flex1 mr-m chart-box is-always-shadow">
                <div class="el-card__header">
                    <div class="flex space-between center-v">
                        <h5> Vulnerabilities </h5>
                    </div>
                </div>
                <div class="el-card__body">
                    <div>
                        <div class="flex border-bottom mb-s">
                            <div class="flex-col center-v center-h flex1 pb-s border-right">
                                <h3 class="mb-xs text-primary">&&VULNTOTAL&&</h3>
                                <span>Total</span>
                            </div>
                            <div class="flex-col center-v center-h flex1 pb-s">
                                <h3 class="mb-xs text-alert">&&VULNCRITICAL&&</h3>
                                <span>Critical</span>
                            </div>
                        </div> <!-- end of first row (flex border-bottom mb-s) -->
                        <div class="flex border-bottom mb-s">
                            <div class="flex-col center-v center-h flex1 pb-s border-right">
                                <h3 class="mb-xs text-danger">&&VULNHIGH&&</h3>
                                <span>High</span>
                            </div>
                            <div class="flex-col center-v center-h flex1 pb-s">
                                <h3 class="mb-xs text-warning">&&VULNMEDIUM&&</h3>
                                <span>Medium</span>
                            </div>
                        </div> <!-- end of second row (flex border-bottom mb-s) -->    
                    </div>  
                </div>
                <!-- <div id="flot-vulnerabilities" style="width:100%;height:300px;"></div> -->
            </div>
        </div>
    </div>

    <div class="row" style="padding-top: 5px; padding-left: 20px; padding-right: 20px">
        <div class="col">
            <div class="el-card flex1 mr-m chart-box is-always-shadow">
                <div class="el-card__header">
                    <div class="flex space-between center-v">
                        <h5> Assurance Policies </h5>
                    </div>
                </div>
                <div class="el-card__body">
                    <div>
                        <div class="flex border-bottom mb-s">
                            <div class="flex-col center-v center-h flex1 pb-s border-right">
                                <h3 class="mb-xs">&&ASSURANCEIMAGE&&</h3>
                                <span>Image</span>
                            </div>
                            <div class="flex-col center-v center-h flex1 pb-s">
                                <h3 class="mb-xs">&&ASSURANCEHOST&&</h3>
                                <span>Host</span>
                            </div>
                        </div> <!-- end of first row (flex border-bottom mb-s) -->
                        <div class="flex border-bottom mb-s">
                            <div class="flex-col center-v center-h flex1 pb-s border-right">
                                <h3 class="mb-xs">&&ASSURANCEFUNCTION&&</h3>
                                <span>Function</span>
                            </div>
                            <div class="flex-col center-v center-h flex1 pb-s">
                                <h3 class="mb-xs">&&ASSURANCEPCF&&</h3>
                                <span>PAS</span>
                            </div>
                        </div> <!-- end of second row (flex border-bottom mb-s) -->    
                    </div>  
                </div>
            </div>
        </div>
    </div>
    
    <div class="row" style="padding-top: 5px; padding-left: 20px; padding-right: 20px">
        <div class="col">
            <div class="el-card flex1 mr-m chart-box is-always-shadow">
                <div class="el-card__header">
                    <div class="flex space-between center-v">
                        <h5> Enforcers - Count: &&ENFORCERCOUNT&& </h5>
                    </div>
                </div>  
                <div class="el-card__body">
                    <div>
                        <div class="table-responsive">
                            <table class="table table-striped table-bordered table-hover enforcers">
                                <thead>
                                    <tr>
                                    <th>Logical Name</th>
                                    <th>Hostname</th>
                                    <th>Type</th>
                                    <th>Status</th>
                                    <th>Mode</th>
                                    </tr>
                                </thead>
                                <tbody>
                                