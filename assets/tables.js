$(document).ready(function() {
    $('#risk').DataTable( {
        "lengthMenu": [[10, 25, 50, -1], [10, 25, 50, "All"]]
    } );
} );

$(document).ready(function() {
    $('#vulnerabilities').DataTable( {
        "order": [[3, 'desc']]
    } );
} );

$(document).ready(function() {
    $('#sensitive').DataTable( {
        "lengthMenu": [[10, 25, 50, -1], [10, 25, 50, "All"]]
    } );
} );

$(document).ready(function() {
    $('#malware').DataTable( {
        "lengthMenu": [[10, 25, 50, -1], [10, 25, 50, "All"]]
    } );
} );