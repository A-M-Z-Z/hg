<?php
session_start(); // Start session

// Check if user is logged in and is an admin
if (!isset($_SESSION['username']) || !isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || $_SESSION['is_admin'] != 1) {
    header("Location: expired");  // Redirect to expired page if not admin
    exit();
}

// Database Connection
$host = 'localhost';
$user = 'root';
$pass = 'root';
$dbname = 'cloudbox';
$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error) die("Database connection failed: " . $conn->connect_error);
$conn->options(MYSQLI_OPT_CONNECT_TIMEOUT, 60);

$username = $_SESSION['username'];
$userid = $_SESSION['user_id'];

// Handle user deletion
if (isset($_GET['delete_user']) && is_numeric($_GET['delete_user'])) {
    $user_id = intval($_GET['delete_user']);
    // Don't allow admin to delete themselves
    if ($user_id != $userid) {
        $deleteStmt = $conn->prepare("DELETE FROM users WHERE id = ?");
        $deleteStmt->bind_param("i", $user_id);
        if ($deleteStmt->execute()) {
            $messages[] = "<div class='alert alert-success'>User deleted successfully.</div>";
        } else {
            $messages[] = "<div class='alert alert-danger'>Error deleting user.</div>";
        }
    } else {
        $messages[] = "<div class='alert alert-danger'>You cannot delete yourself!</div>";
    }
}

// Handle admin promotion/demotion
if (isset($_GET['toggle_admin']) && is_numeric($_GET['toggle_admin'])) {
    $user_id = intval($_GET['toggle_admin']);
    // Don't allow admin to demote themselves
    if ($user_id != $userid) {
        // First check current admin status
        $checkStmt = $conn->prepare("SELECT is_admin FROM users WHERE id = ?");
        $checkStmt->bind_param("i", $user_id);
        $checkStmt->execute();
        $checkStmt->bind_result($is_admin);
        $checkStmt->fetch();
        $checkStmt->close();
        
        // Toggle admin status
        $new_status = $is_admin ? 0 : 1;
        $updateStmt = $conn->prepare("UPDATE users SET is_admin = ? WHERE id = ?");
        $updateStmt->bind_param("ii", $new_status, $user_id);
        if ($updateStmt->execute()) {
            $messages[] = "<div class='alert alert-success'>User admin status updated successfully.</div>";
        } else {
            $messages[] = "<div class='alert alert-danger'>Error updating user admin status.</div>";
        }
    } else {
        $messages[] = "<div class='alert alert-danger'>You cannot change your own admin status!</div>";
    }
}

// Handle storage quota updates
if (isset($_POST['update_quota']) && isset($_POST['user_id']) && isset($_POST['quota_mb'])) {
    $user_id = intval($_POST['user_id']);
    $quota_mb = intval($_POST['quota_mb']);
    
    // Validate the quota (minimum 10MB, maximum 10GB)
    $quota_mb = max(10, min(10240, $quota_mb));
    
    // Convert from MB to bytes
    $quota_bytes = $quota_mb * 1024 * 1024;
    
    $update_quota = $conn->prepare("UPDATE users SET storage_quota = ? WHERE id = ?");
    $update_quota->bind_param("ii", $quota_bytes, $user_id);
    
    if ($update_quota->execute()) {
        $messages[] = "<div class='alert alert-success'>Storage quota updated successfully.</div>";
    } else {
        $messages[] = "<div class='alert alert-danger'>Error updating storage quota.</div>";
    }
}

// Handle file deletion
if (isset($_GET['delete_file']) && is_numeric($_GET['delete_file']) && isset($_GET['view_files']) && is_numeric($_GET['view_files'])) {
    $file_id = intval($_GET['delete_file']);
    $view_user_id = intval($_GET['view_files']);
    
    $deleteFileStmt = $conn->prepare("DELETE FROM files WHERE id = ?");
    $deleteFileStmt->bind_param("i", $file_id);
    if ($deleteFileStmt->execute()) {
        $messages[] = "<div class='alert alert-success'>File deleted successfully.</div>";
    } else {
        $messages[] = "<div class='alert alert-danger'>Error deleting file.</div>";
    }
}

// Handle viewing user files
$view_user_id = isset($_GET['view_files']) && is_numeric($_GET['view_files']) ? intval($_GET['view_files']) : null;

// Initialize messages array if not set
if (!isset($messages)) {
    $messages = [];
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudBOX - Files and Folders</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Custom CSS -->
    <link rel="stylesheet" href="style.css">
    <style>
                .admin-section {
            background-color: #ffffff;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        table, th, td {
            border: 1px solid #e0e0e0;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
        }
        
        th {
            background-color: #f5f5f5;
            font-weight: bold;
        }
        
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        
        tr:hover {
            background-color: #e0e7ff;
        }
        
        .action-btn {
            padding: 6px 12px;
            border-radius: 4px;
            text-decoration: none;
            display: inline-block;
            margin-right: 5px;
            font-size: 14px;
        }
        
        .view-btn {
            background-color: #3b82f6;
            color: white;
        }
        
        .admin-btn {
            background-color: #8b5cf6;
            color: white;
        }
        
        .delete-btn {
            background-color: #ef4444;
            color: white;
        }
        
        .back-btn {
            background-color: #6b7280;
            color: white;
            margin-bottom: 20px;
        }
        
        .stats-container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background-color: #ffffff;
            border-left: 5px solid #4f46e5;
            border-radius: 8px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            flex: 1;
            min-width: 200px;
        }
        
        .stat-title {
            color: #6b7280;
            font-size: 14px;
            margin-bottom: 8px;
        }
        
        .stat-value {
            color: #1f2937;
            font-size: 24px;
            font-weight: bold;
        }

        /* Responsive table handling */
        @media (max-width: 1024px) {
            .admin-section {
                padding: 15px;
                overflow-x: auto;
            }
        }
        
        @media (max-width: 768px) {
            .stats-container {
                flex-direction: column;
            }
            
            .stat-card {
                min-width: 100%;
            }
        }
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .top-bar {
            background-color: #4f46e5;
            padding: 15px;
            display: flex;
            align-items: center;
            color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .logo {
            margin-right: 15px;
        }
        
        .top-bar h1 {
            margin: 0;
            font-size: 22px;
        }
        
        .search-bar {
            margin-left: auto;
        }
        
        .search-bar input {
            border-radius: 20px;
            padding: 8px 15px;
            border: none;
            width: 250px;
        }
        
        .dashboard-nav {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 15px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .dashboard-nav a {
            color: #4b5563;
            text-decoration: none;
            padding: 8px 15px;
            border-radius: 6px;
            transition: background-color 0.2s;
        }
        
        .dashboard-nav a:hover {
            background-color: #f3f4f6;
            color: #4f46e5;
        }
        
        main {
            max-width: 1200px;
            margin: 30px auto;
            padding: 0 20px;
        }
        
        .container-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .item {
            background-color: #fff;
            border-radius: 8px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        
        .item:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        
        .icon {
            font-size: 48px;
            margin-bottom: 15px;
        }
        
        .folder-icon {
            color: #4f46e5;
        }
        
        .file-icon {
            color: #60a5fa;
        }
        
        .name {
            text-align: center;
            font-weight: 500;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            width: 100%;
            margin-bottom: 10px;
        }
        
        .actions {
            display: flex;
            margin-top: 10px;
            gap: 10px;
            width: 100%;
            justify-content: center;
        }
        
        .file-details {
            font-size: 13px;
            color: #6b7280;
            text-align: center;
            margin-top: 5px;
        }
        
        .drag-area {
            border: 2px dashed #d1d5db;
            border-radius: 8px;
            padding: 30px 20px;
            text-align: center;
            transition: border-color 0.3s;
            margin-bottom: 15px;
            position: relative;
            cursor: pointer;
        }
        
        .drag-area.active {
            border-color: #4f46e5;
            background-color: rgba(79, 70, 229, 0.05);
        }
        
        .drag-area i {
            font-size: 48px;
            color: #9ca3af;
            margin-bottom: 15px;
        }
        
        .storage-card {
            background-color: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .storage-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .storage-title {
            font-size: 18px;
            font-weight: 600;
            margin: 0;
        }
        
        .storage-status {
            font-size: 14px;
            color: <?= $usagePercentage > 90 ? '#dc3545' : ($usagePercentage > 70 ? '#fd7e14' : '#198754') ?>;
            font-weight: 500;
        }
        
        .storage-progress-container {
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            margin-bottom: 10px;
            overflow: hidden;
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .storage-progress {
            height: 100%;
            border-radius: 10px;
            background: <?= $usagePercentage > 90 ? 
                        'linear-gradient(90deg, #dc3545 0%, #f44336 100%)' : 
                        ($usagePercentage > 70 ? 
                            'linear-gradient(90deg, #fd7e14 0%, #ffb74d 100%)' : 
                            'linear-gradient(90deg, #198754 0%, #20c997 100%)') ?>;
            width: <?= min(100, $usagePercentage) ?>%;
            transition: width 1s ease;
            position: relative;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .storage-progress-text {
            position: absolute;
            color: <?= $usagePercentage > 50 ? 'white' : '#212529' ?>;
            font-weight: 600;
            font-size: 12px;
            text-shadow: 0 1px 1px rgba(0,0,0,0.2);
            width: 100%;
            text-align: center;
        }
        
        .storage-details {
            display: flex;
            justify-content: space-between;
            font-size: 14px;
            color: #6c757d;
        }
        
        .section-header {
            display: flex;
            align-items: center;
            margin: 30px 0 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #e9ecef;
        }
        
        .section-header i {
            font-size: 24px;
            margin-right: 10px;
            color: #4f46e5;
        }
        
        .section-title {
            font-size: 20px;
            font-weight: 600;
            margin: 0;
            color: #343a40;
        }
        
        .btn-action {
            padding: 6px 12px;
            font-size: 14px;
            border-radius: 6px;
        }
        
        /* Bootstrap adjustments */
        .card {
            border: none;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            border-radius: 10px;
        }
        
        .form-control {
            border-radius: 6px;
            padding: 10px 15px;
        }
        
        .btn-primary {
            background-color: #4f46e5;
            border-color: #4f46e5;
        }
        
        .btn-primary:hover {
            background-color: #4338ca;
            border-color: #4338ca;
        }
        
        .btn-success {
            background-color: #059669;
            border-color: #059669;
        }
        
        .btn-success:hover {
            background-color: #047857;
            border-color: #047857;
        }
        
        .btn-danger {
            background-color: #ef4444;
            border-color: #ef4444;
        }
        
        .btn-danger:hover {
            background-color: #dc2626;
            border-color: #dc2626;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .container-grid {
                grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            }
            
            .search-bar input {
                width: 150px;
            }
        }
    </style>
</head>
<body>
    <div class="top-bar">
        <div class="logo">
            <img src="logo.png" alt="CloudBOX Logo" height="40">
        </div>
        <h1>CloudBOX</h1>
        <div class="search-bar">
            <input type="text" placeholder="Search files and folders..." class="form-control">
        </div>
    </div>
    
    <nav class="dashboard-nav">
        <a href="home"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
        <a href="drive"><i class="fas fa-folder"></i> My Drive</a>
        <?php if(isset($_SESSION['is_admin']) && $_SESSION['is_admin'] == 1): ?>
        <a href="admin"><i class="fas fa-crown"></i> Admin Panel</a>
        <?php endif; ?>
        <a href="shared"><i class="fas fa-share-alt"></i> Shared Files</a>
        <a href="monitoring"><i class="fas fa-chart-line"></i> Monitoring</a>
        <a href="logout"><i class="fas fa-sign-out-alt"></i> Logout</a>
    </nav>

    <main>
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="h3">Welcome, <?= htmlspecialchars($username) ?>!</h1>
        </div>
    </style>
</head>
<body>
    <div class="top-bar">
        <div class="logo">
            <img src="logo.png" alt="CloudBOX Logo" height="40">
        </div>
        <h1>CloudBOX</h1>
        <div class="search-bar">
            <input type="text" placeholder="Search here..." class="form-control">
        </div>
    </div>
    
    <nav class="dashboard-nav">
        <a href="home"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
        <a href="drive"><i class="fas fa-folder"></i> My Drive</a>
        <a href="admin"><i class="fas fa-crown"></i> Admin Panel</a>
        <a href="shared"><i class="fas fa-share-alt"></i> Shared Files</a>
        <a href="monitoring"><i class="fas fa-chart-line"></i> Monitoring</a>
        <a href="logout"><i class="fas fa-sign-out-alt"></i> Logout</a>
    </nav>

    <main>
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="h3">Admin Dashboard</h1>
            <div>
                <span class="text-muted">Welcome, Admin <?= htmlspecialchars($username) ?>!</span>
            </div>
        </div>
        
        <!-- Display messages -->
        <?php foreach ($messages as $message): ?>
            <?= $message ?>
        <?php endforeach; ?>
        
        <?php if ($view_user_id): ?>
            <!-- View User Files Section -->
            <a href="admin" class="btn btn-secondary mb-4">
                <i class="fas fa-arrow-left me-2"></i> Back to Admin Dashboard
            </a>
            <?php
            $userStmt = $conn->prepare("SELECT username FROM users WHERE id = ?");
            $userStmt->bind_param("i", $view_user_id);
            $userStmt->execute();
            $userStmt->bind_result($user_username);
            $userStmt->fetch();
            $userStmt->close();
            ?>
            <div class="card mb-4">
                <div class="card-header bg-white">
                    <h5 class="mb-0"><i class="fas fa-file me-2"></i>Files for User: <?= htmlspecialchars($user_username) ?></h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>File ID</th>
                                    <th>Filename</th>
                                    <th>Size</th>
                                    <th>Type</th>
                                    <th>Upload Date</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                $filesStmt = $conn->prepare("SELECT id, filename, file_size, file_type, created_at FROM files WHERE user_id = ?");
                                $filesStmt->bind_param("i", $view_user_id);
                                $filesStmt->execute();
                                $result = $filesStmt->get_result();
                                
                                if ($result->num_rows > 0) {
                                    while ($file = $result->fetch_assoc()) {
                                        $fileSize = format_file_size($file['file_size']);
                                        echo "<tr>";
                                        echo "<td>" . $file['id'] . "</td>";
                                        echo "<td>" . htmlspecialchars($file['filename']) . "</td>";
                                        echo "<td>" . $fileSize . "</td>";
                                        echo "<td>" . htmlspecialchars($file['file_type']) . "</td>";
                                        echo "<td>" . ($file['created_at'] ?? 'N/A') . "</td>";
                                        echo "<td>
                                            <a href='download.php?id={$file['id']}&admin={$userid}' class='btn btn-sm btn-primary'>
                                                <i class='fas fa-download me-1'></i> Download
                                            </a>
                                            <a href='?delete_file={$file['id']}&view_files={$view_user_id}' class='btn btn-sm btn-danger' 
                                               onclick='return confirm(\"Are you sure you want to delete this file?\");'>
                                                <i class='fas fa-trash me-1'></i> Delete
                                            </a>
                                        </td>";
                                        echo "</tr>";
                                    }
                                } else {
                                    echo "<tr><td colspan='6' class='text-center'>No files found for this user</td></tr>";
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        <?php else: ?>
            <!-- System Stats Section -->
            <div class="stats-container">
                <?php
                // Total Users
                $userCount = $conn->query("SELECT COUNT(*) FROM users")->fetch_row()[0];
                // Total Files
                $fileCount = $conn->query("SELECT COUNT(*) FROM files")->fetch_row()[0];
                // Total Storage Used
                $totalStorage = $conn->query("SELECT SUM(file_size) FROM files")->fetch_row()[0];
                $totalStorageMB = number_format($totalStorage / (1024 * 1024), 2);
                // Admin Count
                $adminCount = $conn->query("SELECT COUNT(*) FROM users WHERE is_admin = 1")->fetch_row()[0];
                ?>
                <div class="stat-card">
                    <div class="stat-title">TOTAL USERS</div>
                    <div class="stat-value"><?= $userCount ?></div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">TOTAL FILES</div>
                    <div class="stat-value"><?= $fileCount ?></div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">STORAGE USED</div>
                    <div class="stat-value"><?= $totalStorageMB ?> MB</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">ADMINS</div>
                    <div class="stat-value"><?= $adminCount ?></div>
                </div>
            </div>
            
            <!-- User Management Section -->
            <div class="card mb-4">
                <div class="card-header bg-white">
                    <h5 class="mb-0"><i class="fas fa-users me-2"></i>User Management</h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Username</th>
                                    <th>Email</th>
                                    <th>Full Name</th>
                                    <th>Storage Used</th>
                                    <th>Storage Quota</th>
                                    <th>Admin Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                $result = $conn->query("SELECT u.id, u.username, u.email, u.full_name, u.is_admin, u.storage_quota, 
                                                      (SELECT SUM(file_size) FROM files WHERE user_id = u.id) as storage 
                                                      FROM users u ORDER BY u.id");
                                
                                while ($user = $result->fetch_assoc()) {
                                    $storageInMB = number_format(($user['storage'] ?? 0) / (1024 * 1024), 2);
                                    $quotaInMB = number_format(($user['storage_quota'] ?? 104857600) / (1024 * 1024), 0);
                                    $adminStatus = $user['is_admin'] == 1 ? 'Admin' : 'User';
                                    $adminBtnText = $user['is_admin'] == 1 ? 'Remove Admin' : 'Make Admin';
                                    
                                    // Calculate usage percentage for progress bar
                                    $usagePercent = ($user['storage'] && $user['storage_quota']) 
                                        ? min(100, round(($user['storage'] / $user['storage_quota']) * 100)) 
                                        : 0;
                                    
                                    $barColor = $usagePercent > 90 ? '#ef4444' : ($usagePercent > 70 ? '#f59e0b' : '#22c55e');
                                    
                                    echo "<tr>";
                                    echo "<td>" . $user['id'] . "</td>";
                                    echo "<td>" . htmlspecialchars($user['username']) . "</td>";
                                    echo "<td>" . htmlspecialchars($user['email']) . "</td>";
                                    echo "<td>" . htmlspecialchars($user['full_name']) . "</td>";
                                    echo "<td>
                                          <div class='progress mb-2' style='height: 8px;'>
                                            <div class='progress-bar' role='progressbar' style='width: {$usagePercent}%; background-color: {$barColor};'></div>
                                          </div>
                                          {$storageInMB} MB ({$usagePercent}%)
                                        </td>";
                                    echo "<td>
                                          <form method='post' class='d-flex'>
                                            <input type='hidden' name='user_id' value='{$user['id']}'>
                                            <div class='input-group input-group-sm'>
                                              <input type='number' name='quota_mb' value='{$quotaInMB}' min='10' max='10240' class='form-control'>
                                              <button type='submit' name='update_quota' class='btn btn-primary'>MB</button>
                                            </div>
                                          </form>
                                        </td>";
                                    echo "<td>" . $adminStatus . "</td>";
                                    echo "<td>
                                        <div class='btn-group btn-group-sm'>
                                            <a href='?view_files={$user['id']}' class='btn btn-primary'>
                                                <i class='fas fa-folder-open me-1'></i> View Files
                                            </a>
                                            <a href='?toggle_admin={$user['id']}' class='btn btn-secondary'>
                                                <i class='fas " . ($user['is_admin'] == 1 ? "fa-user" : "fa-crown") . " me-1'></i> {$adminBtnText}
                                            </a>
                                            <a href='?delete_user={$user['id']}' class='btn btn-danger' 
                                               onclick='return confirm(\"Are you sure you want to delete this user? All their files will be deleted as well.\");'>
                                                <i class='fas fa-trash me-1'></i> Delete
                                            </a>
                                        </div>
                                    </td>";
                                    echo "</tr>";
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- System Logs Section -->
            <div class="card mb-4">
                <div class="card-header bg-white">
                    <h5 class="mb-0"><i class="fas fa-history me-2"></i>Recent System Activity</h5>
                </div>
                <div class="card-body">
                    <p class="card-text">This section displays recent login attempts, file uploads, and other system activities.</p>
                    
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>User</th>
                                    <th>Action</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="4" class="text-center">Logging system not implemented yet. This feature will be available soon.</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </main>

    <!-- Bootstrap Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // Hide messages after 3 seconds
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alert => {
            // Create a Bootstrap alert instance
            const bsAlert = new bootstrap.Alert(alert);
            // Use Bootstrap's hide method
            bsAlert.close();
        });
    }, 3000);
    </script>
</body>
</html>

<?php
// Helper function to format file size
function format_file_size($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } else {
        return $bytes . ' bytes';
    }
}
?>
