package com.sentineldroid

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.navigation.fragment.NavHostFragment
import androidx.navigation.ui.setupWithNavController
import com.sentineldroid.databinding.ActivityMainBinding
import com.sentineldroid.service.SentinelMonitorService
import com.sentineldroid.ui.settings.SettingsFragment

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val locationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val granted = permissions[Manifest.permission.ACCESS_FINE_LOCATION] == true ||
                      permissions[Manifest.permission.ACCESS_COARSE_LOCATION] == true
        if (!granted) {
            Toast.makeText(this,
                "Location permission denied — Wi-Fi encryption detection requires it on Android 10+",
                Toast.LENGTH_LONG).show()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            SentinelMonitorService.start(this)
        } else {
            Toast.makeText(this,
                "Background monitoring needs notification permission to keep watching.",
                Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Block screenshots of sensitive security data
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Restore saved settings (HIBP key etc.) before any scan
        SettingsFragment.loadSavedSettings(this)

        // Navigation
        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        val navController = navHostFragment.navController
        binding.bottomNavView.setupWithNavController(navController)

        requestLocationIfNeeded()
        startBackgroundMonitoring()
    }

    private fun requestLocationIfNeeded() {
        val fine   = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
        val coarse = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION)
        if (fine == PackageManager.PERMISSION_GRANTED ||
            coarse == PackageManager.PERMISSION_GRANTED) return

        if (shouldShowRequestPermissionRationale(Manifest.permission.ACCESS_FINE_LOCATION)) {
            AlertDialog.Builder(this)
                .setTitle("Location Permission")
                .setMessage(
                    "SentinelDroid needs location permission to read your Wi-Fi network name " +
                    "and check its encryption type (WPA2/WPA3/Open).\n\n" +
                    "Android requires this since Android 10. Your physical location is " +
                    "never sent anywhere — all scanning is on-device."
                )
                .setPositiveButton("Grant") { _, _ ->
                    locationPermissionLauncher.launch(arrayOf(
                        Manifest.permission.ACCESS_FINE_LOCATION,
                        Manifest.permission.ACCESS_COARSE_LOCATION
                    ))
                }
                .setNegativeButton("Not now", null)
                .show()
        } else {
            locationPermissionLauncher.launch(arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION
            ))
        }
    }

    /** Start the persistent foreground monitor (after asking for required perms). */
    private fun startBackgroundMonitoring() {
        if (!SentinelMonitorService.isEnabled(this)) return

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }

        SentinelMonitorService.start(this)
        promptBatteryOptimizationOnce()
    }

    /** Prompt the user (one time) to exempt the app from battery optimisation,
     *  so Android won't kill the watcher service after a few hours of doze. */
    private fun promptBatteryOptimizationOnce() {
        val prefs = getSharedPreferences("sentineldroid_prompts", Context.MODE_PRIVATE)
        if (prefs.getBoolean("battery_prompt_shown", false)) return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return

        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (pm.isIgnoringBatteryOptimizations(packageName)) {
            prefs.edit().putBoolean("battery_prompt_shown", true).apply()
            return
        }

        AlertDialog.Builder(this)
            .setTitle("Keep monitoring running")
            .setMessage(
                "For SentinelDroid to keep watching for spyware while your phone is " +
                "asleep, please allow it to ignore battery optimisation.\n\n" +
                "Tap 'Allow', then choose SentinelDroid → Don't optimise."
            )
            .setPositiveButton("Allow") { _, _ ->
                try {
                    startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                } catch (_: Exception) { }
                prefs.edit().putBoolean("battery_prompt_shown", true).apply()
            }
            .setNegativeButton("Skip") { _, _ ->
                prefs.edit().putBoolean("battery_prompt_shown", true).apply()
            }
            .show()
    }
}
