<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

	<style>
        .wrapper,textarea{
            overflow:auto
        }
        .flex{
            display:flex;
            align-items:center
        }
        .flex-wrap{
            flex-wrap:wrap
        }
        .flex1{
            flex:1
        }
        .pl30{
            padding-left:30px!important
        }
        .pl10{
            padding-left:10px!important
        }
        .px10{
            padding-left:10px;
            padding-right:10px
        }
        .severity{
            color:#fff;
            border-radius:3px;
            padding:3px 6px
        }
        .severity.negligible{
            background:#5cef97
        }
        .severity.high{
            background:#e0443d
        }
        .severity.critical{
            background:#8b0000
        }
        .severity.medium{
            background:#f79421
        }
        .severity.low{
            background:#e1c930
        }
        progress,sub,sup{
            vertical-align:baseline
        }
        button,hr,input{
            overflow:visible
        }
        [type=checkbox],[type=radio],legend{
            box-sizing:border-box;
            padding:0
        }
        html{
            -ms-text-size-adjust:100%;
            -webkit-text-size-adjust:100%
        }
        article,aside,details,figcaption,figure,footer,header,main,menu,nav,section,summary{
            display:block
        }
        audio,canvas,progress,video{
            display:inline-block
        }
        audio:not([controls]){
            display:none;
            height:0
        }
        [hidden],template{
            display:none
        }
        a{
            background-color:transparent;
            -webkit-text-decoration-skip:objects
        }
        a:active,a:hover{
            outline-width:0
        }
        abbr[title]{
            border-bottom:none;
            text-decoration:underline;
            text-decoration:underline dotted
        }
        b,strong{
            font-weight:bolder
        }
        dfn{
            font-style:italic
        }
        h1{
            font-size:2em;
            margin:.67em 0
        }
        mark{
            background-color:#ff0;
            color:#000
        }
        small{
            font-size:80%
        }
        sub,sup{
            font-size:75%;
            line-height:0;
            position:relative
        }
        sub{
            bottom:-.25em
        }
        sup{
            top:-.5em
        }
        img{
            border-style:none
        }
        svg:not(:root){
            overflow:hidden
        }
        code,kbd,pre,samp{
            font-family:monospace,monospace;
            font-size:1em
        }
        figure{
            margin:1em 40px
        }
        hr{
            box-sizing:content-box;
            height:0
        }
        button,input,select,textarea{
            font:inherit;
            margin:0
        }
        h1,optgroup{
            font-weight:700
        }
        button,select{
            text-transform:none
        }
        [type=reset],[type=submit],button,html [type=button]{
            -webkit-appearance:button
        }
        [type=reset]::-moz-focus-inner,[type=submit]::-moz-focus-inner,[type=button]::-moz-focus-inner,button::-moz-focus-inner{
            border-style:none;
            padding:0
        }
        [type=reset]:-moz-focusring,[type=submit]:-moz-focusring,[type=button]:-moz-focusring,button:-moz-focusring{
            outline:ButtonText dotted 1px
        }
        fieldset{
            border:1px solid silver;
            margin:0 2px;
            padding:.35em .625em .75em
        }
        legend{
            color:inherit;
            display:table;
            max-width:100%;
            white-space:normal
        }
        .resources,.resources .more-info{
            display:none
        }
        [type=number]::-webkit-inner-spin-button,[type=number]::-webkit-outer-spin-button{
            height:auto
        }
        [type=search]{
            -webkit-appearance:textfield;
            outline-offset:-2px
        }
        [type=search]::-webkit-search-cancel-button,[type=search]::-webkit-search-decoration{
            -webkit-appearance:none
        }
        ::-webkit-input-placeholder{
            color:inherit;
            opacity:.54
        }
        ::-webkit-file-upload-button{
            -webkit-appearance:button;
            font:inherit
        }
        h2{
            font-size:1.2em
        }
        .success{
            margin:2em auto;
            max-width:400px;
            padding:1em;
            font-size:1.6em;
            background-color:#91b94f;
            color:#fff
        }
        table{
            width:100%;
            margin:1em auto;
            border-collapse:collapse
        }
        .table-data{
            margin-top:0;
            width:calc(100% - 5px);
            text-align:left;
            background:#f9f9f9;
            border:1px solid #1f9fba;
            border-bottom:none;
            border-right: 2px solid #1f9fba;
        }
        #cves.table-data{
            border:none
        }
        .table-data:last-child{
            border-bottom:1px solid #1f9fba
        }
        .table-data caption{
            margin-bottom:.6em
        }
        .table-data .data-item,.table-data td,.table-data th{
            padding:7px 10px;
            border:1px solid #1f9fba;
            position:relative
        }
        .table-data .data-item{
            border:none;
        }
        .table-data .data-item:last-child{
            border-right:none
        }
        .table-data th{
            border:none;
            background:#fff
        }
        .more-info td,.more-info th{
            border:1px solid #ccc!important
        }
        .table-data th:first-child{
            padding-left:32px
        }
        .table-data .chevron-down,.table-data .chevron-right,.table-data a{
            text-decoration:none;
            color:#08b1d5
        }
        .table-data a:hover{
            text-decoration:underline
        }
        .table-data tr:hover{
            background:#d5d2d0
        }
        .table-data tbody tr:nth-child(even) td{
            background-color:#daf1f6
        }
        #summary tr:first-child td{
            padding:.75em;
            font-size:1.5em;
            border:1px solid #000;
            color:#fff;
            text-shadow:1px 1px 1px #000
        }
        #summary tr:first-child td:nth-child(1){
            background-color:#e0443d
        }
        #summary tr:first-child td:nth-child(2){
            background-color:#f79421
        }
        #summary tr:first-child td:nth-child(3){
            background-color:#e1c930
        }
        #summary tr:first-child td:nth-child(4){
            background-color:#5cef97
        }
        #summary tr:first-child td:nth-child(5){
            background-color:#1280c4
        }
        #summary tr:last-child td{
            padding-top:4px;
            font-size:.9em;
            text-transform:uppercase
        }
        #disallow{
            text-align:left;
            max-width:500px;
            margin:2em auto 0;
            background-color:#e0adad;
            padding:10px;
            border:1px solid #e0443d
        }
        #disallow li{
            line-height:24px
        }
        #disallow p{
            margin-bottom:10px
        }
        .wrapper{
            height:calc(100vh - 315px)
        }
        .resources .headers span{
            font-weight:500
        }
        .vulns,input[type=checkbox].group-by:checked~.wrapper .resources{
            display:block
        }
        .more-info,input[type=checkbox].group-by:checked~.wrapper .vulns{
            display:none
        }
        .more-info td{
            background:#fff!important;
            font-size:14px
        }
        .more-info>td{
            background:#ececec!important
        }
        .more-info tr:hover td{
            background:#f9f9f9!important
        }
        .more-info ul{
            list-style:none;
            text-align:left
        }
        .more-info{
            width:100%;
            background:0 0!important;
            border-top:1px solid #1f9fba
        }
        input[type=checkbox].expand:checked~.more-info{
            display:block
        }
        input[type=checkbox].expand:checked~.data-item .chevron-down{
            display:inline-block
        }
        .aqua-logo span,.chevron-down,input[type=checkbox].expand:checked~.data-item .chevron-right{
            display:none
        }
        body>p{
            margin-top:2em
        }
        .bold{
            font-weight:700
        }
        label.data-item{
            color:#08b1d5;
            cursor:pointer
        }
        .chevron-down,.chevron-right{
            font-size:10px;
            position:relative;
            top:-2px
        }
        .aqua-logo{
            display:block;
            margin:0 auto;
            width:144px;
            height:52px;
            background-repeat:no-repeat;
            background-image:url(data:image/png;base64,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)
        }
        *{
            box-sizing:border-box;
            margin:0;
            padding:0
        }
        body,html{
            max-height:100%;
            overflow:hidden;
            font-family:"Lucida Grande","Lucida Sans",Arial,sans-serif;
            color:#464547
        }
        .mt20{
            margin-top:20px
        }
        .mb10{
            margin-bottom:10px
        }
        .aqua-container{
            background:#ccc;
        }
        .clearfix::after{
            display:block;
            content:"";
            clear:both
        }
        .header{
            height:50px;
            line-height:50px;
            background:#000
        }
        .header .logo{
            width:100px;
            margin-top:7px;
            margin-left:10px
        }
        .content{
            margin:30px;
            background:#fff;
            height:calc(100vh - 110px)
        }
        .tabs{
            display:flex;
            flex-wrap:wrap;
            padding-left:20px
        }
        .label{
            width:auto
        }
        input[type=checkbox].expand,input[type=radio].tab{
            display:none
        }
        input[type=radio].tab+.label{
            padding:10px;
            color:#999;
            cursor:pointer
        }
        input[type=radio].tab:checked+.label{
            color:#2b2b2b;
            border:1px solid #ddd;
            border-bottom:0;
            border-radius:3px 3px 0 0
        }
        input[type=radio].tab:checked+.label:after{
            content:"";
            position:absolute;
            height:1px;
            width:calc(100% - 2px);
            background:#fff;
            left:1px;
            bottom:-1px;
            z-index:1000
        }
        input[type=radio].tab:checked+.label+.panel{
            display:block
        }
        .panel{
            display:none;
            clear:both;
            height:calc(100% - 20px);
            overflow:auto;
            border-top:1px solid #ddd;
            padding:20px;
            order:99;
            width:100%
        }
        .content>.title{
            padding:15px 20px;
            margin-bottom:10px;
            border-bottom:0
        }
        .assurance-checks li,.title{
            border-bottom:1px solid #ddd
        }
        .content>.title h1{
            margin-bottom:5px;
            font-size:24px
        }
        .content>.title span{
            font-size:16px
        }
        .box{
            padding:25px 20px;
            border:1px solid #ddd
        }
        .image-status{
            background:#f7f7f7
        }
        .image-status .icon-check,.image-status .icon-warning-triangle{
            width:60px;
            height:60px;
            float:left
        }
        .image-status h2,.image-status h5{
            padding-left:70px;
            margin-top:5px
        }
        .image-status h5{
            font-size:14px;
            font-weight:400
        }
        .title{
            padding:0 0 10px;
            margin:0;
            font-weight:400;
            font-size:16px
        }
        .vuln-nums{
            padding:10px
        }
        .vuln-nums li{
            list-style:none;
            float:left;
            padding:5px 10px;
            border-right:1px solid #ddd;
            font-size:12px
        }
        .vuln-nums li:last-child{
            border-right:none
        }
        .square{
            border-radius:3px;
            width:15px;
            height:15px;
            display:inline-block;
            position:relative;
            top:3px
        }
        .darkred{
        background:#9d0000;
        }
        .red{
            background:#e0443d
        }
        .orange{
            background:#f79421
        }
        .yellow{
            background:#e1c930
        }
        .green{
            background:#a5cf4f
        }
        .text-alert{
            color:#e0443d;
            fill:#e0443d
        }
        .text-success{
            color:#a5cf4f;
            fill:#a5cf4f
        }
        .assurance-checks li{
            list-style:none;
            padding:10px 5px;
            font-size:14px
        }
        .assurance-checks .icon-warning-triangle{
            width:20px;
            position:relative;
            top:3px;
            margin-right:5px
        }
        .ellipsis{
            display:inline-block;
            overflow:hidden;
            text-overflow:ellipsis;
            width:700px;
            white-space: nowrap;
        }
    </style>

    <title>&&IMAGE&&:&&TAG&& | Scan Results</title>
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
    <div class="title">
        <h1>Scan Report: &&IMAGE&&:&&TAG&& </h1>
        <span>From Registry: &&REGISTRY&&</span>
    </div>
    <div class="tabs">
		<input type="radio" class="tab" name="tabs" id="tab1" checked>
		<label for="tab1" class="label">Risk</label>
		<div class="panel tab1">