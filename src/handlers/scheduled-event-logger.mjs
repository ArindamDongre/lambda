import pkg from "pg";
const { Client } = pkg;
import AWS from "aws-sdk";
import dotenv from "dotenv";

// Load environment variables from .env file
dotenv.config();

export const scheduledEventLoggerHandler = async () => {
  const client = new Client({
    host: process.env.PGHOST,
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    database: process.env.PGDATABASE,
    ssl: {
      rejectUnauthorized: false, // Set to true if you have proper SSL certificates
    },
  });

  try {
    // Connect to PostgreSQL
    await client.connect();
    console.log("Connected to PostgreSQL");

    // Create the table if it doesn't exist
    await client.query(`
      CREATE TABLE IF NOT EXISTS iam_users (
        UserId VARCHAR PRIMARY KEY,
        UserName VARCHAR,
        Arn VARCHAR,
        CreateDate TIMESTAMP,
        PasswordLastUsed TIMESTAMP,
        LastSynced TIMESTAMP,
        isDeleted BOOLEAN DEFAULT false
      )
    `);

    // Fetch deleted IAM users using CloudTrail
    const cloudtrail = new AWS.CloudTrail();
    const eventParamsUser = {
      LookupAttributes: [
        {
          AttributeKey: "EventName",
          AttributeValue: "DeleteUser",
        },
      ],
      StartTime: new Date(new Date().getTime() - 24 * 60 * 60 * 1000), // Last 24 hours
      EndTime: new Date(),
    };

    const userEvents = await cloudtrail.lookupEvents(eventParamsUser).promise();
    const deletedUsers = userEvents.Events.map((event) => {
      const eventData = JSON.parse(event.CloudTrailEvent);
      return eventData.requestParameters.userName;
    });

    // Mark deleted users in PostgreSQL
    for (const deletedUser of deletedUsers) {
      await client.query(
        `UPDATE iam_users SET isDeleted = true WHERE UserName = $1 AND isDeleted = false`,
        [deletedUser]
      );
      console.log(`Marked user ${deletedUser} as deleted in PostgreSQL`);
    }

    // Fetch all IAM users, handling pagination
    const iam = new AWS.IAM();
    let users = [];
    let marker;
    do {
      const params = {
        Marker: marker,
      };
      const iamUsers = await iam.listUsers(params).promise();
      users = users.concat(iamUsers.Users);
      marker = iamUsers.Marker; // AWS SDK sets Marker if there are more users to fetch
    } while (marker);

    // const currentUserIds = new Set(); // Track current IAM user IDs
    for (const user of users) {
      const { UserName, UserId, Arn, CreateDate, PasswordLastUsed } = user;

      // currentUserIds.add(UserId); // Add to set of current user IDs

      // Use upsert to insert the user if it doesn't exist, or update it if it does
      await client.query(
        `INSERT INTO iam_users (UserId, UserName, Arn, CreateDate, PasswordLastUsed, LastSynced, isDeleted)
         VALUES ($1, $2, $3, $4, $5, $6, false)
         ON CONFLICT (UserId) 
         DO UPDATE SET UserName = EXCLUDED.UserName, Arn = EXCLUDED.Arn, CreateDate = EXCLUDED.CreateDate, PasswordLastUsed = EXCLUDED.PasswordLastUsed, LastSynced = EXCLUDED.LastSynced, isDeleted = false`,
        [UserId, UserName, Arn, CreateDate, PasswordLastUsed, new Date()]
      );
    }

    // Fetch all IAM users from PostgreSQL to identify users to mark as deleted
    // const result = await client.query(
    //   `SELECT UserId FROM iam_users WHERE isDeleted = false`
    // );
    // const dbUserIds = result.rows.map((row) => row.userid);

    // // Identify and update users that no longer exist in IAM
    // for (const dbUserId of dbUserIds) {
    //   if (!currentUserIds.has(dbUserId)) {
    //     await client.query(
    //       `UPDATE iam_users SET isDeleted = true WHERE UserId = $1`,
    //       [dbUserId]
    //     );
    //     console.log(`Marked user ${dbUserId} as deleted in PostgreSQL`);
    //   }
    // }

    // Create the table if it doesn't exist
    await client.query(`
      CREATE TABLE IF NOT EXISTS iam_groups (
        GroupId VARCHAR PRIMARY KEY,
        GroupName VARCHAR,
        Arn VARCHAR,
        CreateDate TIMESTAMP,
        LastSynced TIMESTAMP,
        isDeleted BOOLEAN DEFAULT false
      )
    `);
  
    // Fetch deleted IAM groups using CloudTrail
    const eventParamsGroup = {
      LookupAttributes: [
        {
          AttributeKey: "EventName",
          AttributeValue: "DeleteGroup",
        },
      ],
      StartTime: new Date(new Date().getTime() - 24 * 60 * 60 * 1000), // Last 24 hours
      EndTime: new Date(),
    };

    const groupEvents = await cloudtrail.lookupEvents(eventParamsGroup).promise();
    const deletedGroups = groupEvents.Events.map((event) => {
      const eventData = JSON.parse(event.CloudTrailEvent);
      return eventData.requestParameters.groupName;
    });

    // Mark deleted groups in PostgreSQL
    for (const deletedGroup of deletedGroups) {
      await client.query(
        `UPDATE iam_groups SET isDeleted = true WHERE GroupName = $1 AND isDeleted = false`,
        [deletedGroup]
      );
      console.log(`Marked group ${deletedGroup} as deleted in PostgreSQL`);
    }


    // Fetch all IAM groups, handling pagination
    let groups = [];
    let groupMarker;
    do {
      const params = {
        Marker: groupMarker,
      };
      const iamGroups = await iam.listGroups(params).promise();
      groups = groups.concat(iamGroups.Groups);
      groupMarker = iamGroups.Marker; // AWS SDK sets Marker if there are more groups to fetch
    } while (groupMarker);

    // const currentGroupIds = new Set(); // Track current IAM group IDs
    for (const group of groups) {
      const { GroupName, GroupId, Arn, CreateDate } = group;

      // currentGroupIds.add(GroupId); // Add to set of current group IDs

      // Use upsert to insert the group if it doesn't exist, or update it if it does
      await client.query(
        `INSERT INTO iam_groups (GroupId, GroupName, Arn, CreateDate, LastSynced, isDeleted)
         VALUES ($1, $2, $3, $4, $5, false)
         ON CONFLICT (GroupId) 
         DO UPDATE SET GroupName = EXCLUDED.GroupName, Arn = EXCLUDED.Arn, CreateDate = EXCLUDED.CreateDate, LastSynced = EXCLUDED.LastSynced, isDeleted = false`,
        [GroupId, GroupName, Arn, CreateDate, new Date()]
      );
    }

    // Fetch all IAM groups from PostgreSQL to identify groups to mark as deleted
    // const groupResult = await client.query(
    //   `SELECT GroupId FROM iam_groups WHERE isDeleted = false`
    // );
    // const dbGroupIds = groupResult.rows.map((row) => row.groupid);

    // // Identify and update groups that no longer exist in IAM
    // for (const dbGroupId of dbGroupIds) {
    //   if (!currentGroupIds.has(dbGroupId)) {
    //     await client.query(
    //       `UPDATE iam_groups SET isDeleted = true WHERE GroupId = $1`,
    //       [dbGroupId]
    //     );
    //     console.log(`Marked group ${dbGroupId} as deleted in PostgreSQL`);
    //   }
    // }
    
    console.log("IAM users and groups have been synced successfully");
  } catch (err) {
    console.error("An error occurred during the sync process:", err);
  } finally {
    await client.end();
    console.log("PostgreSQL connection closed");
  }
};
