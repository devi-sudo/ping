// ==================== SIMPLE CARD ENROLLMENT SYSTEM ====================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const XLSX = require('xlsx');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = admin.firestore();
const auth = admin.auth();

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// ==================== MIDDLEWARES ====================

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Admin middleware
const requireAdmin = async (req, res, next) => {
  try {
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    
    if (userDoc.exists && userDoc.data().role === 'admin') {
      next();
    } else {
      res.status(403).json({ error: 'Admin access required' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// ==================== AUTH ENDPOINTS ====================

// 1. Teacher/Admin Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Find user in Firestore
    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('email', '==', email).get();

    if (snapshot.empty) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const userDoc = snapshot.docs[0];
    const user = userDoc.data();

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create JWT token
    const token = jwt.sign(
      { 
        uid: userDoc.id, 
        email: user.email, 
        role: user.role,
        name: user.name 
      }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: userDoc.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// 2. Register Admin (First time setup)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user already exists
    const snapshot = await db.collection('users').where('email', '==', email).get();
    if (!snapshot.empty) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user in Firebase Auth
    const firebaseUser = await auth.createUser({
      email,
      password,
      displayName: name
    });

    // Save user data in Firestore
    const userData = {
      uid: firebaseUser.uid,
      name,
      email,
      password: hashedPassword,
      role: 'admin',
      createdAt: new Date()
    };

    await db.collection('users').doc(firebaseUser.uid).set(userData);

    // Generate JWT token
    const token = jwt.sign(
      { 
        uid: firebaseUser.uid, 
        email, 
        role: 'admin',
        name 
      }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      user: {
        id: firebaseUser.uid,
        name,
        email,
        role: 'admin'
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: error.message });
  }
});

// 3. Verify Token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// ==================== RFID ENDPOINTS ====================

// 4. Receive RFID Scan from ESP8266
// app.post('/api/rfid/scan', async (req, res) => {
//   try {
//     const { cardId, deviceId } = req.body;

//     console.log('📱 RFID Scan received:', { cardId, deviceId });

//     if (!cardId) {
//       return res.status(400).json({ error: 'Card ID required' });
//     }

//     // Find student by card ID
//     const studentsRef = db.collection('students');
//     const snapshot = await studentsRef.where('cardId', '==', cardId).where('isActive', '==', true).get();

//     if (snapshot.empty) {
//       return res.json({ 
//         status: 'not_found',
//         message: 'Card not registered or student inactive' 
//       });
//     }

//     const studentDoc = snapshot.docs[0];
//     const student = { id: studentDoc.id, ...studentDoc.data() };

//     // Check today's attendance
//     const today = new Date();
//     today.setHours(0, 0, 0, 0);

//     const attendanceRef = db.collection('attendance');
//     const todayQuery = await attendanceRef
//       .where('studentId', '==', student.id)
//       .where('date', '>=', today)
//       .limit(1)
//       .get();

//     let attendanceData;
//     let isCheckIn = false;

//     if (todayQuery.empty) {
//       // CHECK-IN
//       isCheckIn = true;
//       const now = new Date();
      
//       // Check if late (after 8:30 AM)
//       const isLate = now.getHours() > 8 || (now.getHours() === 8 && now.getMinutes() > 30);
      
//       attendanceData = {
//         studentId: student.id,
//         cardId: student.cardId,
//         name: student.name,
//         className: student.className,
//         rollNumber: student.rollNumber,
//         checkIn: now,
//         date: now,
//         status: isLate ? 'Late' : 'Present',
//         type: 'checkin',
//         deviceId: deviceId || 'unknown'
//       };

//       await attendanceRef.add(attendanceData);
//       console.log('✅ Check-in:', student.name, isLate ? '(Late)' : '');

//     } else {
//       // CHECK-OUT
//       const attendanceDoc = todayQuery.docs[0];
//       const existingRecord = attendanceDoc.data();

//       if (!existingRecord.checkOut) {
//         await attendanceDoc.ref.update({
//           checkOut: new Date(),
//           type: 'checkout'
//         });

//         attendanceData = { ...existingRecord, checkOut: new Date() };
//         console.log('👋 Check-out:', student.name);
//       } else {
//         return res.json({ 
//           status: 'already_checked_out',
//           name: student.name,
//           message: 'Already checked out today'
//         });
//       }
//     }

//     // Update real-time status in Firebase Database (for real-time monitoring)
//     const realtimeRef = admin.database().ref('scans');
//     const scanData = {
//       cardId,
//       name: student.name,
//       className: student.className,
//       type: isCheckIn ? 'checkin' : 'checkout',
//       timestamp: Date.now(),
//       status: isCheckIn ? (attendanceData.status === 'Late' ? 'Late' : 'Present') : 'Checked Out'
//     };
    
//     await realtimeRef.push(scanData);

//     // Update device last seen
//     if (deviceId) {
//       const deviceRef = db.collection('devices').doc(deviceId);
//       await deviceRef.set({
//         lastSeen: new Date(),
//         status: 'online',
//         lastCard: cardId
//       }, { merge: true });
//     }

//     return res.json({ 
//       status: isCheckIn ? 'login' : 'logout',
//       name: student.name,
//       className: student.className,
//       message: isCheckIn ? 
//         `Welcome ${student.name} (${student.className})` : 
//         `Goodbye ${student.name} (${student.className})`,
//       time: new Date().toLocaleTimeString(),
//       isLate: attendanceData.status === 'Late'
//     });

//   } catch (error) {
//     console.error('❌ RFID Scan error:', error);
//     res.status(500).json({ error: error.message });
//   }
// });

// ==================== STUDENT MANAGEMENT ====================

// 5. Get All Students
app.get('/api/students', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const snapshot = await db.collection('students').orderBy('createdAt', 'desc').get();
    const students = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));
    res.json(students);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 6. Add New Student
app.post('/api/students', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const student = req.body;
    
    // Validate required fields
    if (!student.name || !student.cardId || !student.className) {
      return res.status(400).json({ error: 'Name, Card ID, and Class are required' });
    }

    // Check if card ID already exists
    const existing = await db.collection('students')
      .where('cardId', '==', student.cardId)
      .get();
    
    if (!existing.empty) {
      return res.status(400).json({ error: 'Card ID already exists' });
    }

    const studentData = {
      ...student,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const docRef = await db.collection('students').add(studentData);
    
    res.status(201).json({ 
      id: docRef.id, 
      ...studentData,
      message: 'Student added successfully' 
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 7. Update Student
app.put('/api/students/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;

    await db.collection('students').doc(id).update({
      ...updateData,
      updatedAt: new Date()
    });

    res.json({ message: 'Student updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 8. Delete Student
app.delete('/api/students/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await db.collection('students').doc(id).delete();
    res.json({ message: 'Student deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 9. Toggle Student Status
app.patch('/api/students/:id/toggle', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const studentRef = db.collection('students').doc(id);
    const studentDoc = await studentRef.get();

    if (!studentDoc.exists) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const currentStatus = studentDoc.data().isActive;
    await studentRef.update({
      isActive: !currentStatus,
      updatedAt: new Date()
    });

    res.json({ 
      message: `Student ${!currentStatus ? 'activated' : 'deactivated'} successfully`,
      isActive: !currentStatus
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== ATTENDANCE & REPORTS ====================

// 10. Get Attendance Records
app.get('/api/attendance', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { date, className, studentId, page = 1, limit = 50 } = req.query;
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);

    let query = db.collection('attendance');

    if (date) {
      const startDate = new Date(date);
      startDate.setHours(0, 0, 0, 0);
      const endDate = new Date(date);
      endDate.setHours(23, 59, 59, 999);
      query = query.where('date', '>=', startDate).where('date', '<=', endDate);
    }

    if (className) {
      query = query.where('className', '==', className);
    }

    if (studentId) {
      query = query.where('studentId', '==', studentId);
    }

    // Get total count for pagination
    const countSnapshot = await query.get();
    const total = countSnapshot.size;

    // Apply pagination
    const snapshot = await query
      .orderBy('date', 'desc')
      .limit(limitNum)
      .offset((pageNum - 1) * limitNum)
      .get();

    const records = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({
      records,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum)
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 11. Get Dashboard Statistics
app.get('/api/dashboard/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    // Get counts
    const totalStudents = (await db.collection('students').get()).size;
    
    const todayAttendance = await db.collection('attendance')
      .where('date', '>=', today)
      .where('date', '<', tomorrow)
      .get();
    
    const presentToday = todayAttendance.size;

    // Get unique classes
    const studentsSnap = await db.collection('students').get();
    const classesSet = new Set();
    studentsSnap.forEach(doc => {
      const student = doc.data();
      if (student.className) {
        classesSet.add(student.className);
      }
    });

    // Get weekly data
    const weekStart = new Date(today);
    weekStart.setDate(weekStart.getDate() - weekStart.getDay());
    
    const weeklyData = [];
    for (let i = 0; i < 7; i++) {
      const day = new Date(weekStart);
      day.setDate(day.getDate() + i);
      
      const dayStart = new Date(day);
      dayStart.setHours(0, 0, 0, 0);
      const dayEnd = new Date(day);
      dayEnd.setHours(23, 59, 59, 999);

      const dayAttendance = await db.collection('attendance')
        .where('date', '>=', dayStart)
        .where('date', '<=', dayEnd)
        .get();

      weeklyData.push({
        day: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][day.getDay()],
        date: day.toISOString().split('T')[0],
        present: dayAttendance.size
      });
    }

    res.json({
      totalStudents,
      presentToday,
      totalClasses: classesSet.size,
      classes: Array.from(classesSet),
      weeklyData,
      attendanceRate: totalStudents > 0 ? Math.round((presentToday / totalStudents) * 100) : 0
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 12. Export Attendance to Excel
app.get('/api/export/excel', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { startDate, endDate, className } = req.query;

    let query = db.collection('attendance');

    if (startDate && endDate) {
      const start = new Date(startDate);
      start.setHours(0, 0, 0, 0);
      const end = new Date(endDate);
      end.setHours(23, 59, 59, 999);
      query = query.where('date', '>=', start).where('date', '<=', end);
    }

    if (className && className !== 'all') {
      query = query.where('className', '==', className);
    }

    const snapshot = await query.orderBy('date', 'desc').get();
    
    // Prepare data for Excel
    const data = [];
    snapshot.docs.forEach(doc => {
      const record = doc.data();
      data.push({
        'Date': record.date?.toDate ? record.date.toDate().toLocaleDateString() : 'N/A',
        'Student Name': record.name || 'N/A',
        'Class': record.className || 'N/A',
        'Roll Number': record.rollNumber || 'N/A',
        'Card ID': record.cardId || 'N/A',
        'Check-in Time': record.checkIn?.toDate ? record.checkIn.toDate().toLocaleTimeString() : 'N/A',
        'Check-out Time': record.checkOut?.toDate ? record.checkOut.toDate().toLocaleTimeString() : 'N/A',
        'Status': record.status || 'N/A',
        'Attendance Type': record.type || 'N/A'
      });
    });

    // Create workbook
    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.json_to_sheet(data);
    
    // Style the header
    const headerStyle = {
      fill: { fgColor: { rgb: "4472C4" } },
      font: { color: { rgb: "FFFFFF" }, bold: true }
    };

    XLSX.utils.book_append_sheet(wb, ws, 'Attendance Report');

    // Generate buffer
    const excelBuffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    // Set headers for download
    const filename = `attendance-report-${new Date().toISOString().split('T')[0]}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    
    res.send(excelBuffer);

  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: error.message });
  }
});

// 13. Get Monthly Report Data
app.get('/api/reports/monthly', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { year, month, className } = req.query;
    const yearNum = parseInt(year) || new Date().getFullYear();
    const monthNum = parseInt(month) || new Date().getMonth() + 1;

    const startDate = new Date(yearNum, monthNum - 1, 1);
    const endDate = new Date(yearNum, monthNum, 0);
    endDate.setHours(23, 59, 59, 999);

    let query = db.collection('attendance')
      .where('date', '>=', startDate)
      .where('date', '<=', endDate);

    if (className && className !== 'all') {
      query = query.where('className', '==', className);
    }

    const snapshot = await query.get();

    // Group by date
    const reportData = {};
    const daysInMonth = new Date(yearNum, monthNum, 0).getDate();

    // Initialize all days
    for (let day = 1; day <= daysInMonth; day++) {
      const dateStr = `${yearNum}-${monthNum.toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}`;
      reportData[dateStr] = {
        date: dateStr,
        present: 0,
        late: 0,
        absent: 0,
        totalStudents: 0
      };
    }

    // Get total students per class
    let studentsQuery = db.collection('students').where('isActive', '==', true);
    if (className && className !== 'all') {
      studentsQuery = studentsQuery.where('className', '==', className);
    }
    const studentsSnap = await studentsQuery.get();
    const totalStudents = studentsSnap.size;

    // Process attendance records
    snapshot.docs.forEach(doc => {
      const record = doc.data();
      const dateStr = record.date?.toDate ? record.date.toDate().toISOString().split('T')[0] : null;
      
      if (dateStr && reportData[dateStr]) {
        if (record.status === 'Present') {
          reportData[dateStr].present++;
        } else if (record.status === 'Late') {
          reportData[dateStr].late++;
        }
      }
    });

    // Calculate absent for each day
    Object.values(reportData).forEach(day => {
      day.totalStudents = totalStudents;
      day.absent = totalStudents - (day.present + day.late);
      day.attendanceRate = totalStudents > 0 ? Math.round((day.present / totalStudents) * 100) : 0;
    });

    res.json({
      year: yearNum,
      month: monthNum,
      totalStudents,
      dailyData: Object.values(reportData)
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== DEVICE MANAGEMENT ====================

// 14. Get Device Status
app.get('/api/devices/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const devicesRef = db.collection('devices');
    const snapshot = await devicesRef.get();
    
    const devices = [];
    snapshot.forEach(doc => {
      const device = doc.data();
      const isOnline = device.lastSeen && 
        (new Date() - device.lastSeen.toDate()) < 5 * 60 * 1000; // 5 minutes
      
      devices.push({
        id: doc.id,
        ...device,
        status: isOnline ? 'online' : 'offline',
        lastSeen: device.lastSeen ? device.lastSeen.toDate() : null
      });
    });

    res.json(devices);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 15. Manual Scan (for testing)
app.post('/api/manual/scan', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { cardId } = req.body;
    
    if (!cardId) {
      return res.status(400).json({ error: 'Card ID required' });
    }

    // Simulate RFID scan
    const scanResult = await processRFIDScan(cardId, 'manual-device');
    
    res.json(scanResult);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Helper function for processing scans
async function processRFIDScan(cardId, deviceId = 'manual') {
  const studentsRef = db.collection('students');
  const snapshot = await studentsRef.where('cardId', '==', cardId).where('isActive', '==', true).get();

  if (snapshot.empty) {
    return { 
      status: 'not_found',
      message: 'Card not registered or student inactive' 
    };
  }

  const studentDoc = snapshot.docs[0];
  const student = { id: studentDoc.id, ...studentDoc.data() };

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const attendanceRef = db.collection('attendance');
  const todayQuery = await attendanceRef
    .where('studentId', '==', student.id)
    .where('date', '>=', today)
    .limit(1)
    .get();

  let attendanceData;
  let isCheckIn = false;

  if (todayQuery.empty) {
    // CHECK-IN
    isCheckIn = true;
    const now = new Date();
    const isLate = now.getHours() > 8 || (now.getHours() === 8 && now.getMinutes() > 30);
    
    attendanceData = {
      studentId: student.id,
      cardId: student.cardId,
      name: student.name,
      className: student.className,
      rollNumber: student.rollNumber,
      checkIn: now,
      date: now,
      status: isLate ? 'Late' : 'Present',
      type: 'checkin',
      deviceId: deviceId
    };

    await attendanceRef.add(attendanceData);

    // Update real-time
    const realtimeRef = admin.database().ref('scans');
    await realtimeRef.push({
      cardId,
      name: student.name,
      className: student.className,
      type: 'checkin',
      timestamp: Date.now(),
      status: isLate ? 'Late' : 'Present',
      source: 'manual'
    });

  } else {
    // CHECK-OUT
    const attendanceDoc = todayQuery.docs[0];
    const existingRecord = attendanceDoc.data();

    if (!existingRecord.checkOut) {
      await attendanceDoc.ref.update({
        checkOut: new Date(),
        type: 'checkout'
      });

      // Update real-time
      const realtimeRef = admin.database().ref('scans');
      await realtimeRef.push({
        cardId,
        name: student.name,
        className: student.className,
        type: 'checkout',
        timestamp: Date.now(),
        status: 'Checked Out',
        source: 'manual'
      });
    } else {
      return { 
        status: 'already_checked_out',
        name: student.name,
        message: 'Already checked out today'
      };
    }
  }

  return { 
    status: isCheckIn ? 'login' : 'logout',
    name: student.name,
    className: student.className,
    message: isCheckIn ? 
      `Manual check-in: ${student.name} (${student.className})` : 
      `Manual check-out: ${student.name} (${student.className})`,
    time: new Date().toLocaleTimeString()
  };
}

// ==================== REAL-TIME ENDPOINTS ====================

// 16. Get Real-time Scans (WebSocket alternative)
app.get('/api/realtime/scans', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const realtimeRef = admin.database().ref('scans');
    
    const snapshot = await realtimeRef
      .orderByChild('timestamp')
      .limitToLast(limit)
      .once('value');
    
    const scans = [];
    snapshot.forEach(childSnapshot => {
      scans.push({
        id: childSnapshot.key,
        ...childSnapshot.val()
      });
    });
    
    res.json(scans.reverse()); // Newest first
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// Add this to your index.js file in the ==================== DEVICE MANAGEMENT ==================== section
// 14. Get Device Status (Fixed Version)
app.get('/api/devices/status', authenticateToken, async (req, res) => {
  try {
    const devicesRef = db.collection('devices');
    const snapshot = await devicesRef.get();
    
    const devices = [];
    
    if (snapshot.empty) {
      return res.json(devices); // Return empty array if no devices
    }
    
    snapshot.forEach(doc => {
      const device = doc.data();
      const lastSeen = device.lastSeen ? device.lastSeen.toDate() : null;
      
      // Check if device is online (last seen within 5 minutes)
      let status = 'offline';
      if (lastSeen) {
        const timeDiff = new Date() - lastSeen;
        status = timeDiff < 5 * 60 * 1000 ? 'online' : 'offline';
      }
      
      devices.push({
        id: doc.id,
        name: device.name || doc.id,
        lastSeen: lastSeen,
        lastCard: device.lastCard || null,
        status: status
      });
    });

    res.json(devices);
  } catch (error) {
    console.error('Device status error:', error);
    res.status(500).json({ error: error.message });
  }
});

// 17. Add device registration endpoint (when ESP8266 first connects)
app.post('/api/devices/register', async (req, res) => {
  try {
    const { deviceId, deviceName } = req.body;
    
    if (!deviceId) {
      return res.status(400).json({ error: 'Device ID required' });
    }
    
    const deviceRef = db.collection('devices').doc(deviceId);
    const deviceDoc = await deviceRef.get();
    
    const deviceData = {
      id: deviceId,
      name: deviceName || `RFID Scanner ${deviceId}`,
      lastSeen: new Date(),
      status: 'online',
      registeredAt: new Date(),
      type: 'rfid_scanner'
    };
    
    if (deviceDoc.exists) {
      // Update existing device
      await deviceRef.update({
        lastSeen: new Date(),
        status: 'online',
        name: deviceName || deviceDoc.data().name
      });
    } else {
      // Create new device
      await deviceRef.set(deviceData);
    }
    
    res.json({ 
      status: 'success',
      message: 'Device registered/updated',
      deviceId: deviceId
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
//////////////---EXTRA WE CAN REMOVE
// ==================== DEVICE MODE MANAGEMENT ====================

// 21. Set device mode
app.post('/api/devices/:deviceId/mode', authenticateToken, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { mode } = req.body;
    
    if (!['attendance', 'enrollment'].includes(mode)) {
      return res.status(400).json({ error: 'Invalid mode' });
    }
    
    const deviceRef = db.collection('devices').doc(deviceId);
    const deviceDoc = await deviceRef.get();
    
    if (!deviceDoc.exists) {
      // Create device if doesn't exist
      await deviceRef.set({
        id: deviceId,
        name: `Device ${deviceId}`,
        mode: mode,
        lastSeen: new Date(),
        status: 'online',
        registeredAt: new Date()
      });
    } else {
      await deviceRef.update({
        mode: mode,
        lastSeen: new Date(),
        status: 'online'
      });
    }
    
    res.json({ 
      status: 'success',
      message: `Device switched to ${mode} mode`,
      deviceId: deviceId,
      mode: mode
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 22. Get device mode
app.get('/api/devices/:deviceId/mode', async (req, res) => {
  try {
    const { deviceId } = req.params;
    
    const deviceRef = db.collection('devices').doc(deviceId);
    const deviceDoc = await deviceRef.get();
    
    if (!deviceDoc.exists) {
      return res.json({ 
        mode: 'attendance',
        exists: false 
      });
    }
    
    const deviceData = deviceDoc.data();
    
    res.json({ 
      mode: deviceData.mode || 'attendance',
      exists: true,
      lastSeen: deviceData.lastSeen
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 23. Check for enrollment cards
app.get('/api/enrollment/check', authenticateToken, async (req, res) => {
  try {
    // Get all devices in enrollment mode
    const devicesRef = db.collection('devices');
    const snapshot = await devicesRef
      .where('mode', '==', 'enrollment')
      .where('lastSeen', '>', new Date(Date.now() - 15000)) // Last 15 seconds
      .get();
    
    if (snapshot.empty) {
      return res.json({ 
        status: 'waiting',
        message: 'No active devices in enrollment mode'
      });
    }
    
    // Find the most recent scan
    let latestCard = null;
    snapshot.forEach(doc => {
      const device = doc.data();
      if (device.lastCard && device.lastSeen) {
        const lastSeen = device.lastSeen.toDate ? device.lastSeen.toDate() : new Date(device.lastSeen);
        if (!latestCard || lastSeen > latestCard.timestamp) {
          latestCard = {
            cardId: device.lastCard,
            deviceId: doc.id,
            deviceName: device.name,
            timestamp: lastSeen
          };
        }
      }
    });
    
    if (!latestCard) {
      return res.json({ 
        status: 'waiting',
        message: 'Waiting for card scan...'
      });
    }
    
    // Check if card is already enrolled
    const studentsRef = db.collection('students');
    const studentSnap = await studentsRef.where('cardId', '==', latestCard.cardId).get();
    
    if (!studentSnap.empty) {
      return res.json({
        status: 'already_enrolled',
        cardId: latestCard.cardId,
        message: 'This card is already assigned to a student'
      });
    }
    
    res.json({
      status: 'pending',
      cardId: latestCard.cardId,
      deviceId: latestCard.deviceId,
      deviceName: latestCard.deviceName,
      timestamp: latestCard.timestamp,
      message: 'Card ready for enrollment'
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 24. Update device status
app.post('/api/devices/status/update', async (req, res) => {
  try {
    const { deviceId, status, mode } = req.body;
    
    if (!deviceId) {
      return res.status(400).json({ error: 'Device ID required' });
    }
    
    const deviceRef = db.collection('devices').doc(deviceId);
    
    await deviceRef.set({
      lastSeen: new Date(),
      status: status || 'online',
      mode: mode || 'attendance'
    }, { merge: true });
    
    res.json({ 
      status: 'success',
      message: 'Device status updated'
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 25. Quick enrollment endpoint
app.post('/api/enrollment/quick', authenticateToken, async (req, res) => {
  try {
    const { cardId, name, age, className, rollNumber } = req.body;
    
    if (!cardId || !name || !className) {
      return res.status(400).json({ error: 'Card ID, Name, and Class are required' });
    }
    
    // Check if card already exists
    const existing = await db.collection('students')
      .where('cardId', '==', cardId)
      .get();
    
    if (!existing.empty) {
      return res.status(400).json({ error: 'Card ID already enrolled' });
    }
    
    const studentData = {
      name,
      age: parseInt(age) || 0,
      className,
      rollNumber: rollNumber || '',
      cardId,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    const docRef = await db.collection('students').add(studentData);
    
    // Clear the card from device (optional)
    const devicesRef = db.collection('devices');
    const deviceSnap = await devicesRef.where('lastCard', '==', cardId).get();
    
    if (!deviceSnap.empty) {
      const deviceDoc = deviceSnap.docs[0];
      await deviceDoc.ref.update({
        lastCard: null
      });
    }
    
    res.json({
      status: 'success',
      message: 'Student enrolled successfully',
      studentId: docRef.id,
      cardId: cardId,
      student: studentData
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 26. Update RFID scan endpoint to handle mode properly
// app.post('/api/rfid/scan', async (req, res) => {
//   try {
//     const { cardId, deviceId, mode = 'attendance' } = req.body;

//     console.log('📱 RFID Scan received:', { cardId, deviceId, mode });

//     if (!cardId) {
//       return res.status(400).json({ error: 'Card ID required' });
//     }

//     // ============ UPDATE DEVICE STATUS ============
//     if (deviceId) {
//       const deviceRef = db.collection('devices').doc(deviceId);
//       const deviceData = {
//         lastSeen: new Date(),
//         status: 'online',
//         lastCard: cardId,
//         mode: mode
//       };
      
//       const deviceDoc = await deviceRef.get();
//       if (!deviceDoc.exists) {
//         // Auto-register device if not exists
//         deviceData.id = deviceId;
//         deviceData.name = `Device ${deviceId}`;
//         deviceData.registeredAt = new Date();
//         await deviceRef.set(deviceData);
//       } else {
//         await deviceRef.set(deviceData, { merge: true });
//       }
//     }

//     // ============ ENROLLMENT MODE ============
//     if (mode === 'enrollment') {
//       console.log('🎯 Enrollment mode - Card detected:', cardId);
      
//       // Check if card already enrolled
//       const studentsRef = db.collection('students');
//       const studentSnap = await studentsRef.where('cardId', '==', cardId).get();
      
//       if (!studentSnap.empty) {
//         return res.json({
//           status: 'already_enrolled',
//           cardId: cardId,
//           message: 'This card is already assigned to a student'
//         });
//       }
      
//       return res.json({
//         status: 'enrollment',
//         cardId: cardId,
//         message: 'Card ready for enrollment',
//         time: new Date().toLocaleTimeString()
//       });
//     }

//     // ============ ATTENDANCE MODE ============
//     // Rest of your existing attendance logic...
//     const studentsRef = db.collection('students');
//     const snapshot = await studentsRef.where('cardId', '==', cardId).where('isActive', '==', true).get();

//     if (snapshot.empty) {
//       return res.json({ 
//         status: 'not_found',
//         cardId: cardId,
//         message: 'Card not registered or student inactive' 
//       });
//     }

//     const studentDoc = snapshot.docs[0];
//     const student = { id: studentDoc.id, ...studentDoc.data() };

//     const today = new Date();
//     today.setHours(0, 0, 0, 0);

//     const attendanceRef = db.collection('attendance');
//     const todayQuery = await attendanceRef
//       .where('studentId', '==', student.id)
//       .where('date', '>=', today)
//       .limit(1)
//       .get();

//     let attendanceData;
//     let isCheckIn = false;

//     if (todayQuery.empty) {
//       // CHECK-IN
//       isCheckIn = true;
//       const now = new Date();
//       const isLate = now.getHours() > 8 || (now.getHours() === 8 && now.getMinutes() > 30);
      
//       attendanceData = {
//         studentId: student.id,
//         cardId: student.cardId,
//         name: student.name,
//         className: student.className,
//         rollNumber: student.rollNumber,
//         checkIn: now,
//         date: now,
//         status: isLate ? 'Late' : 'Present',
//         type: 'checkin',
//         deviceId: deviceId || 'unknown',
//         mode: mode
//       };

//       await attendanceRef.add(attendanceData);

//       // Update real-time
//       const realtimeRef = admin.database().ref('scans');
//       await realtimeRef.push({
//         cardId,
//         name: student.name,
//         className: student.className,
//         type: 'checkin',
//         timestamp: Date.now(),
//         status: isLate ? 'Late' : 'Present',
//         deviceId: deviceId
//       });

//     } else {
//       // CHECK-OUT
//       const attendanceDoc = todayQuery.docs[0];
//       const existingRecord = attendanceDoc.data();

//       if (!existingRecord.checkOut) {
//         await attendanceDoc.ref.update({
//           checkOut: new Date(),
//           type: 'checkout'
//         });

//         // Update real-time
//         const realtimeRef = admin.database().ref('scans');
//         await realtimeRef.push({
//           cardId,
//           name: student.name,
//           className: student.className,
//           type: 'checkout',
//           timestamp: Date.now(),
//           status: 'Checked Out',
//           deviceId: deviceId
//         });
//       } else {
//         return res.json({ 
//           status: 'already_checked_out',
//           name: student.name,
//           message: 'Already checked out today'
//         });
//       }
//     }

//     return res.json({ 
//       status: isCheckIn ? 'login' : 'logout',
//       name: student.name,
//       className: student.className,
//       message: isCheckIn ? 
//         `Welcome ${student.name} (${student.className})` : 
//         `Goodbye ${student.name} (${student.className})`,
//       time: new Date().toLocaleTimeString(),
//       isLate: attendanceData && attendanceData.status === 'Late'
//     });

//   } catch (error) {
//     console.error('❌ RFID Scan error:', error);
//     res.status(500).json({ error: error.message });
//   }
// });

// ==================== HEALTH CHECK ====================

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK',
    timestamp: new Date().toISOString(),
    service: 'RFID Attendance API',
    version: '1.0.0'
  });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
  console.log(`📡 API available at: http://localhost:${port}`);
  console.log(`🏥 Health check: http://localhost:${port}/health`);
});
// Store scanned cards in memory (or use Redis in production)

let scannedCards = [];

// 27. Get all scanned cards (for frontend polling)
app.get('/api/cards/scanning', authenticateToken, async (req, res) => {
  try {
    // Get recent cards from all devices (last 30 seconds)
    const thirtySecondsAgo = new Date(Date.now() - 30000);
    
    const devicesRef = db.collection('devices');
    const snapshot = await devicesRef
      .where('lastSeen', '>', thirtySecondsAgo)
      .get();
    
    const cards = [];
    const processedCardIds = new Set();
    
    snapshot.forEach(doc => {
      const device = doc.data();
      if (device.lastCard && device.lastSeen) {
        const lastSeen = device.lastSeen.toDate ? device.lastSeen.toDate() : new Date(device.lastSeen);
        
        // Only include cards scanned in last 30 seconds
        if (lastSeen > thirtySecondsAgo && !processedCardIds.has(device.lastCard)) {
          processedCardIds.add(device.lastCard);
          
          cards.push({
            id: device.lastCard,
            deviceId: doc.id,
            deviceName: device.name,
            timestamp: lastSeen,
            isRecent: true
          });
        }
      }
    });
    
    // Check if cards are already assigned to students
    for (const card of cards) {
      const studentsRef = db.collection('students');
      const studentSnap = await studentsRef.where('cardId', '==', card.id).get();
      card.isAssigned = !studentSnap.empty;
      
      if (!studentSnap.empty) {
        const student = studentSnap.docs[0].data();
        card.assignedTo = student.name;
      }
    }
    
    res.json({ 
      cards: cards.sort((a, b) => b.timestamp - a.timestamp), // Newest first
      total: cards.length
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 28. Simple enrollment endpoint
app.post('/api/students/enroll', authenticateToken, async (req, res) => {
  try {
    const { name, age, className, rollNumber, cardId, isActive = true } = req.body;
    
    // Validate required fields
    if (!name || !className || !cardId) {
      return res.status(400).json({ error: 'Name, Class, and Card ID are required' });
    }
    
    // Check if card already exists
    const existingStudent = await db.collection('students')
      .where('cardId', '==', cardId)
      .get();
    
    if (!existingStudent.empty) {
      return res.status(400).json({ 
        error: 'This card is already assigned to another student',
        existingStudent: existingStudent.docs[0].data().name
      });
    }
    
    // Create student data
    const studentData = {
      name,
      age: parseInt(age) || 0,
      className,
      rollNumber: rollNumber || '',
      cardId,
      isActive: isActive !== false,
      enrolledAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    // Add to database
    const docRef = await db.collection('students').add(studentData);
    
    // Log enrollment activity
    await db.collection('enrollment_logs').add({
      studentId: docRef.id,
      cardId,
      name,
      className,
      enrolledAt: new Date(),
      action: 'enrollment'
    });
    
    // Clear this card from recent scans (optional)
    const devicesRef = db.collection('devices');
    const deviceSnap = await devicesRef.where('lastCard', '==', cardId).get();
    
    if (!deviceSnap.empty) {
      const deviceDoc = deviceSnap.docs[0];
      await deviceDoc.ref.update({
        lastCard: null,
        enrollmentStatus: 'completed'
      });
    }
    
    res.json({
      success: true,
      message: 'Student enrolled successfully',
      studentId: docRef.id,
      cardId: cardId,
      student: studentData
    });
    
  } catch (error) {
    console.error('Enrollment error:', error);
    res.status(500).json({ error: error.message });
  }
});

// 29. Clear scanned cards
app.post('/api/cards/clear', authenticateToken, async (req, res) => {
  try {
    // Clear lastCard from all devices
    const devicesRef = db.collection('devices');
    const snapshot = await devicesRef.get();
    
    const batch = db.batch();
    snapshot.forEach(doc => {
      batch.update(doc.ref, { lastCard: null });
    });
    
    await batch.commit();
    
    res.json({ 
      success: true,
      message: 'All scanned cards cleared',
      cleared: snapshot.size
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 30. Update the RFID scan endpoint to be simpler
app.post('/api/rfid/scan', async (req, res) => {
  try {
    const { cardId, deviceId } = req.body;

    console.log('📱 RFID Scan received:', { cardId, deviceId });

    if (!cardId) {
      return res.status(400).json({ error: 'Card ID required' });
    }

    // Update device with scanned card
    if (deviceId) {
      const deviceRef = db.collection('devices').doc(deviceId);
      await deviceRef.set({
        lastSeen: new Date(),
        status: 'online',
        lastCard: cardId
      }, { merge: true });
    }

    // Check if card is enrolled (for attendance)
    const studentsRef = db.collection('students');
    const snapshot = await studentsRef.where('cardId', '==', cardId).where('isActive', '==', true).get();

    if (snapshot.empty) {
      // Card not enrolled - could be for enrollment
      return res.json({ 
        status: 'not_enrolled',
        cardId: cardId,
        message: 'Card not enrolled yet',
        canEnroll: true
      });
    }

    // Card is enrolled - process attendance
    const studentDoc = snapshot.docs[0];
    const student = { id: studentDoc.id, ...studentDoc.data() };

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const attendanceRef = db.collection('attendance');
    const todayQuery = await attendanceRef
      .where('studentId', '==', student.id)
      .where('date', '>=', today)
      .limit(1)
      .get();

    if (todayQuery.empty) {
      // CHECK-IN
      const now = new Date();
      const isLate = now.getHours() > 8 || (now.getHours() === 8 && now.getMinutes() > 30);
      
      const attendanceData = {
        studentId: student.id,
        cardId: student.cardId,
        name: student.name,
        className: student.className,
        rollNumber: student.rollNumber,
        checkIn: now,
        date: now,
        status: isLate ? 'Late' : 'Present',
        type: 'checkin',
        deviceId: deviceId || 'unknown'
      };

      await attendanceRef.add(attendanceData);

      // Update real-time
      const realtimeRef = admin.database().ref('scans');
      await realtimeRef.push({
        cardId,
        name: student.name,
        className: student.className,
        type: 'checkin',
        timestamp: Date.now(),
        status: isLate ? 'Late' : 'Present',
        deviceId: deviceId
      });

      return res.json({ 
        status: 'checkin',
        name: student.name,
        className: student.className,
        message: `Welcome ${student.name} (${student.className})`,
        time: now.toLocaleTimeString(),
        isLate: isLate
      });

    } else {
      // CHECK-OUT
      const attendanceDoc = todayQuery.docs[0];
      const existingRecord = attendanceDoc.data();

      if (!existingRecord.checkOut) {
        await attendanceDoc.ref.update({
          checkOut: new Date(),
          type: 'checkout'
        });

        // Update real-time
        const realtimeRef = admin.database().ref('scans');
        await realtimeRef.push({
          cardId,
          name: student.name,
          className: student.className,
          type: 'checkout',
          timestamp: Date.now(),
          status: 'Checked Out',
          deviceId: deviceId
        });

        return res.json({ 
          status: 'checkout',
          name: student.name,
          className: student.className,
          message: `Goodbye ${student.name} (${student.className})`,
          time: new Date().toLocaleTimeString()
        });
      } else {
        return res.json({ 
          status: 'already_checked_out',
          name: student.name,
          message: 'Already checked out today'
        });
      }
    }

  } catch (error) {
    console.error('❌ RFID Scan error:', error);
    res.status(500).json({ error: error.message });
  }
});
