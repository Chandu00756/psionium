import 'package:flutter/material.dart';
import 'package:syncfusion_flutter_charts/charts.dart';
import 'package:page_transition/page_transition.dart';
import 'package:flutter/animation.dart';
import 'file_management_screen.dart';
import 'encrypt_decrypt.dart';

class HomeScreen extends StatefulWidget {
  @override
  _HomeScreenState createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with SingleTickerProviderStateMixin {
  late AnimationController _animationController;
  late Animation<double> _fadeAnimation;
  late Animation<double> _scaleAnimation;
  late Animation<Offset> _slideAnimation;
  bool _isDarkMode = true;
  List<NotificationItem> _notifications = [
    NotificationItem(
      icon: Icons.warning,
      title: "Potential quantum threat detected",
      subtitle: "10 minutes ago",
      color: Colors.red,
    ),
    NotificationItem(
      icon: Icons.link,
      title: "New blockchain transaction",
      subtitle: "1 hour ago",
      color: Colors.blue,
    ),
  ];

  @override
  void initState() {
    super.initState();
    _animationController = AnimationController(
      vsync: this,
      duration: Duration(milliseconds: 1500),
    );

    _fadeAnimation = Tween<double>(begin: 0, end: 1).animate(
      CurvedAnimation(
        parent: _animationController,
        curve: Curves.easeInOut,
      ),
    );

    _scaleAnimation = Tween<double>(begin: 0.8, end: 1).animate(
      CurvedAnimation(
        parent: _animationController,
        curve: Curves.easeInOut,
      ),
    );

    _slideAnimation = Tween<Offset>(
      begin: Offset(0, 0.5),
      end: Offset.zero,
    ).animate(
      CurvedAnimation(
        parent: _animationController,
        curve: Curves.easeInOut,
      ),
    );

    _animationController.forward();
  }

  @override
  void dispose() {
    _animationController.dispose();
    super.dispose();
  }
//Theme toggler
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _isDarkMode ? Color(0xFF0A0E21) : Colors.grey[200],
      appBar: AppBar(
        title: Text(
          "pSIONIUM Dock",
          style: TextStyle(
            color: Color(0xFF00FFA3), // Teal accent
            fontWeight: FontWeight.bold,
            fontSize: 24,
          ),
        ),
        backgroundColor: _isDarkMode ? Color(0xFF0A0E21) : Colors.white,
        elevation: 0,
        actions: [
          IconButton(
            icon: Icon(Icons.notifications, color: Color(0xFF00FFA3)),
            onPressed: () {
              _showNotificationsDialog();
            },
          ),
          IconButton(
            icon: Icon(Icons.search, color: Color(0xFF00FFA3)),
            onPressed: () {
              _openGlobalSearch();
            },
          ),
          IconButton(
            icon: Icon(_isDarkMode ? Icons.light_mode : Icons.dark_mode, color: Color(0xFF00FFA3)),
            onPressed: () {
              setState(() {
                _isDarkMode = !_isDarkMode;
              });
            },
          ),
          PopupMenuButton<String>(
            icon: Icon(Icons.account_circle, color: Color(0xFF00FFA3)),
            onSelected: (value) {
              if (value == "logout") {
                _handleLogout();
              } else if (value == "settings") {
                _navigateToSettings();
              }
            },
            itemBuilder: (BuildContext context) {
              return [
                PopupMenuItem(
                  value: "profile",
                  child: Text("Profile"),
                ),
                PopupMenuItem(
                  value: "settings",
                  child: Text("Settings"),
                ),
                PopupMenuItem(
                  value: "logout",
                  child: Text("Logout"),
                ),
              ];
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              SlideTransition(
                position: _slideAnimation,
                child: FadeTransition(
                  opacity: _fadeAnimation,
                  child: ScaleTransition(
                    scale: _scaleAnimation,
                    child: _buildDashboardSection(context),
                  ),
                ),
              ),
              SizedBox(height: 20),
              SlideTransition(
                position: _slideAnimation,
                child: FadeTransition(
                  opacity: _fadeAnimation,
                  child: ScaleTransition(
                    scale: _scaleAnimation,
                    child: _buildQuickActionsSection(context),
                  ),
                ),
              ),
              SizedBox(height: 20),
              SlideTransition(
                position: _slideAnimation,
                child: FadeTransition(
                  opacity: _fadeAnimation,
                  child: ScaleTransition(
                    scale: _scaleAnimation,
                    child: _buildNotificationsSection(context),
                  ),
                ),
              ),
              SizedBox(height: 20),
              SlideTransition(
                position: _slideAnimation,
                child: FadeTransition(
                  opacity: _fadeAnimation,
                  child: ScaleTransition(
                    scale: _scaleAnimation,
                    child: _buildSystemHealthSection(context),
                  ),
                ),
              ),
              SizedBox(height: 20),
              SlideTransition(
                position: _slideAnimation,
                child: FadeTransition(
                  opacity: _fadeAnimation,
                  child: ScaleTransition(
                    scale: _scaleAnimation,
                    child: _buildFileStorageOverview(),
                  ),
                ),
              ),
              SizedBox(height: 20),
              SlideTransition(
                position: _slideAnimation,
                child: FadeTransition(
                  opacity: _fadeAnimation,
                  child: ScaleTransition(
                    scale: _scaleAnimation,
                    child: _buildAIRecommendations(),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDashboardSection(BuildContext context) {
    return Card(
      color: _isDarkMode ? Colors.black.withOpacity(0.5) : Colors.white,
      elevation: 4,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Dashboard",
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
                color: Color(0xFF00FFA3), // Teal accent
              ),
            ),
            SizedBox(height: 10),
            Row(
              children: [
                Expanded(
                  child: _buildUsageChart(),
                ),
                SizedBox(width: 10),
                Expanded(
                  child: _buildRecentActivities(),
                ),
              ],
            ),
            SizedBox(height: 20),
            _buildQuantumResilientBadge(),
            SizedBox(height: 10),
            _buildBlockchainExplorer(),
            SizedBox(height: 10),
            _buildAIInsights(),
          ],
        ),
      ),
    );
  }

  Widget _buildUsageChart() {
    return SfCartesianChart(
      primaryXAxis: CategoryAxis(),
      series: <ChartSeries>[
        LineSeries<ChartData, String>(
          dataSource: [
            ChartData('Mon', 35),
            ChartData('Tue', 28),
            ChartData('Wed', 34),
            ChartData('Thu', 32),
            ChartData('Fri', 40),
          ],
          xValueMapper: (ChartData data, _) => data.day,
          yValueMapper: (ChartData data, _) => data.usage,
          color: Color(0xFF00FFA3), // Teal accent
        ),
      ],
    );
  }

  Widget _buildRecentActivities() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          "Recent Activities",
          style: TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: _isDarkMode ? Colors.white : Colors.black,
          ),
        ),
        SizedBox(height: 10),
        ListTile(
          leading: Icon(Icons.upload, color: Color(0xFF00FFA3)),
          title: Text("Uploaded file.txt", style: TextStyle(color: _isDarkMode ? Colors.white : Colors.black)),
          subtitle: Text("2 hours ago", style: TextStyle(color: Colors.grey)),
        ),
        ListTile(
          leading: Icon(Icons.lock, color: Color(0xFF00FFA3)),
          title: Text("Encrypted secret.key", style: TextStyle(color: _isDarkMode ? Colors.white : Colors.black)),
          subtitle: Text("4 hours ago", style: TextStyle(color: Colors.grey)),
        ),
      ],
    );
  }

  Widget _buildQuantumResilientBadge() {
    return Row(
      children: [
        Icon(Icons.security, color: Color(0xFF00FFA3)),
        SizedBox(width: 10),
        Text(
          "Quantum-Resilient Encryption: Enabled",
          style: TextStyle(color: Color(0xFF00FFA3), fontWeight: FontWeight.bold),
        ),
      ],
    );
  }

  Widget _buildBlockchainExplorer() {
    return InkWell(
      onTap: () {
        _navigateToBlockchainExplorer();
      },
      child: Row(
        children: [
          Icon(Icons.link, color: Colors.blue),
          SizedBox(width: 10),
          Text(
            "View Blockchain Transactions",
            style: TextStyle(color: Colors.blue, fontWeight: FontWeight.bold),
          ),
        ],
      ),
    );
  }

  Widget _buildAIInsights() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          "AI Insights",
          style: TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: _isDarkMode ? Colors.white : Colors.black,
          ),
        ),
        SizedBox(height: 10),
        Text(
          "You have 5 unprotected files. Encrypt them now!",
          style: TextStyle(color: Colors.orange),
        ),
      ],
    );
  }

  Widget _buildQuickActionsSection(BuildContext context) {
    return Card(
      color: _isDarkMode ? Colors.black.withOpacity(0.5) : Colors.white,
      elevation: 4,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Quick Actions",
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
                color: Color(0xFF00FFA3), // Teal accent
              ),
            ),
            SizedBox(height: 10),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: [
                _buildQuickActionButton(Icons.upload, "Upload File", () {
                  Navigator.push(
                    context,
                    PageTransition(
                      child: FileManagementScreen(),
                      type: PageTransitionType.fade,
                    ),
                  );
                }),
                _buildQuickActionButton(Icons.lock, "Encrypt File", () {
                  Navigator.push(
                    context,
                    PageTransition(
                      child: EncryptionScreen(),
                      type: PageTransitionType.fade,
                    ),
                  );
                }),
                _buildQuickActionButton(Icons.security, "Quantum-Resilient Encrypt", () {
                  _handleQuantumResilientEncryption();
                }),
                _buildQuickActionButton(Icons.link, "Blockchain Audit", () {
                  _navigateToBlockchainAudit();
                }),
                _buildQuickActionButton(Icons.insights, "AI Insights", () {
                  _navigateToAIInsights();
                }),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildQuickActionButton(IconData icon, String label, VoidCallback onPressed) {
    return ElevatedButton.icon(
      onPressed: onPressed,
      icon: Icon(icon, color: Colors.black),
      label: Text(label, style: TextStyle(color: Colors.black)),
      style: ElevatedButton.styleFrom(
        backgroundColor: Color(0xFF00FFA3), // Teal accent
        padding: EdgeInsets.symmetric(horizontal: 16, vertical: 10),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
        ),
      ),
    );
  }

  Widget _buildNotificationsSection(BuildContext context) {
    return Card(
      color: _isDarkMode ? Colors.black.withOpacity(0.5) : Colors.white,
      elevation: 4,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  "Notifications",
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: Color(0xFF00FFA3), // Teal accent
                  ),
                ),
                TextButton(
                  onPressed: () {
                    setState(() {
                      _notifications.clear();
                    });
                  },
                  child: Text(
                    "Clear All",
                    style: TextStyle(color: Colors.red),
                  ),
                ),
              ],
            ),
            SizedBox(height: 10),
            ..._notifications.map((notification) {
              return ListTile(
                leading: Icon(notification.icon, color: notification.color),
                title: Text(notification.title, style: TextStyle(color: _isDarkMode ? Colors.white : Colors.black)),
                subtitle: Text(notification.subtitle, style: TextStyle(color: Colors.grey)),
                trailing: IconButton(
                  icon: Icon(Icons.close, color: _isDarkMode ? Colors.white : Colors.black),
                  onPressed: () {
                    setState(() {
                      _notifications.remove(notification);
                    });
                  },
                ),
              );
            }).toList(),
          ],
        ),
      ),
    );
  }

  Widget _buildSystemHealthSection(BuildContext context) {
    return Card(
      color: _isDarkMode ? Colors.black.withOpacity(0.5) : Colors.white,
      elevation: 4,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "System Health",
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
                color: Color(0xFF00FFA3), // Teal accent
              ),
            ),
            SizedBox(height: 10),
            Row(
              children: [
                Expanded(
                  child: _buildSystemHealthMetric("Quantum-Resilient", "100%", Color(0xFF00FFA3)),
                ),
                Expanded(
                  child: _buildSystemHealthMetric("Blockchain", "95%", Colors.blue),
                ),
                Expanded(
                  child: _buildSystemHealthMetric("AI", "90%", Colors.orange),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSystemHealthMetric(String label, String value, Color color) {
    return Column(
      children: [
        CircularProgressIndicator(
          value: double.parse(value.replaceAll('%', '')) / 100,
          backgroundColor: Colors.grey[800],
          valueColor: AlwaysStoppedAnimation<Color>(color),
        ),
        SizedBox(height: 10),
        Text(label, style: TextStyle(color: _isDarkMode ? Colors.white : Colors.black)),
        Text(value, style: TextStyle(color: color, fontWeight: FontWeight.bold)),
      ],
    );
  }

  Widget _buildFileStorageOverview() {
    return Card(
      color: _isDarkMode ? Colors.black.withOpacity(0.5) : Colors.white,
      elevation: 4,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "Storage Overview",
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
                color: Color(0xFF00FFA3), // Teal accent
              ),
            ),
            SizedBox(height: 10),
            LinearProgressIndicator(
              value: 0.7, // Example: 70% storage used
              backgroundColor: Colors.grey[800],
              valueColor: AlwaysStoppedAnimation<Color>(Color(0xFF00FFA3)),
            ),
            SizedBox(height: 10),
            Text(
              "7 GB of 10 GB used",
              style: TextStyle(color: _isDarkMode ? Colors.white : Colors.black),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAIRecommendations() {
    return Card(
      color: _isDarkMode ? Colors.black.withOpacity(0.5) : Colors.white,
      elevation: 4,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              "AI Recommendations",
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.bold,
                color: Color(0xFF00FFA3), // Teal accent
              ),
            ),
            SizedBox(height: 10),
            Text(
              "1. Encrypt 5 unprotected files.",
              style: TextStyle(color: _isDarkMode ? Colors.white : Colors.black),
            ),
            Text(
              "2. Review recent blockchain transactions.",
              style: TextStyle(color: _isDarkMode ? Colors.white : Colors.black),
            ),
          ],
        ),
      ),
    );
  }

  void _showNotificationsDialog() {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: Text("Notifications"),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: _notifications.map((notification) {
              return ListTile(
                leading: Icon(notification.icon, color: notification.color),
                title: Text(notification.title),
                subtitle: Text(notification.subtitle),
              );
            }).toList(),
          ),
          actions: [
            TextButton(
              onPressed: () {
                Navigator.pop(context);
              },
              child: Text("Close"),
            ),
          ],
        );
      },
    );
  }

  void _openGlobalSearch() {
    showSearch(
      context: context,
      delegate: GlobalSearchDelegate(),
    );
  }

  void _handleLogout() {
    // Implement logout logic
  }

  void _navigateToSettings() {
    // Navigate to settings screen
  }

  void _navigateToBlockchainExplorer() {
    // Navigate to blockchain explorer
  }

  void _handleQuantumResilientEncryption() {
    // Handle quantum-resilient encryption
  }

  void _navigateToBlockchainAudit() {
    // Navigate to blockchain audit
  }

  void _navigateToAIInsights() {
    // Navigate to AI insights
  }
}

class NotificationItem {
  final IconData icon;
  final String title;
  final String subtitle;
  final Color color;

  NotificationItem({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.color,
  });
}

class GlobalSearchDelegate extends SearchDelegate<String> {
  @override
  List<Widget> buildActions(BuildContext context) {
    return [
      IconButton(
        icon: Icon(Icons.clear),
        onPressed: () {
          query = '';
        },
      ),
    ];
  }

  @override
  Widget buildLeading(BuildContext context) {
    return IconButton(
      icon: Icon(Icons.arrow_back),
      onPressed: () {
        close(context, null!);
      },
    );
  }

  @override
  Widget buildResults(BuildContext context) {
    return Center(
      child: Text("Search Results for: $query"),
    );
  }

  @override
  Widget buildSuggestions(BuildContext context) {
    return Center(
      child: Text("Suggestions for: $query"),
    );
  }
}

class ChartData {
  final String day;
  final int usage;

  ChartData(this.day, this.usage);
}