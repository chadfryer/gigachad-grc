# Scheduled Reports

Automate report generation and delivery with scheduled reports.

## Overview

Scheduled Reports help you:
- Automate recurring reports
- Deliver to stakeholders
- Maintain compliance documentation
- Save time on manual reporting

## Report Types

### Available Reports
- **Compliance Summary**: Overall compliance status
- **Risk Summary**: Risk register overview
- **Control Status**: Control implementation status
- **Vendor Summary**: Third-party risk overview
- **Audit Status**: Audit progress and findings
- **Training Compliance**: Training completion rates
- **Custom Reports**: User-defined reports

## Viewing Scheduled Reports

Navigate to **Tools → Scheduled Reports**

### List View
- **Report Name**: Report title
- **Type**: Report category
- **Schedule**: Frequency
- **Next Run**: Next scheduled run
- **Recipients**: Delivery list
- **Status**: Active/Paused

## Creating Scheduled Reports

### Create Report
1. Click **Create Scheduled Report**
2. Select report type
3. Configure report:
   - **Name**: Report title
   - **Description**: Report purpose
4. Set parameters:
   - Date range
   - Filters
   - Grouping options
5. Configure schedule:
   - **Frequency**: Daily, Weekly, Monthly
   - **Day/Time**: When to run
6. Set delivery:
   - **Recipients**: Email addresses
   - **Format**: PDF, Excel, CSV
7. Click **Create**

### Schedule Options

| Frequency | Description |
|-----------|-------------|
| **Daily** | Every day at specified time |
| **Weekly** | Specific day of week |
| **Monthly** | Specific day of month |
| **Quarterly** | Every 3 months |
| **Custom** | Custom cron expression |

## Managing Reports

### Edit Schedule
1. Click on report
2. Modify settings
3. Save changes

### Pause/Resume
1. Click report menu (⋮)
2. Select **Pause** or **Resume**

### Run Now
Generate report immediately:
1. Click **Run Now**
2. Report generates
3. Download or auto-deliver

### Delete
1. Click report menu (⋮)
2. Select **Delete**
3. Confirm

## Report Parameters

### Date Ranges
Configure report period:
- **Last 7 days**
- **Last 30 days**
- **Last quarter**
- **Last year**
- **Custom range**

### Filters
Include specific data:
- By category
- By status
- By owner
- By department

### Format Options
- **PDF**: Formatted, shareable
- **Excel**: Data analysis
- **CSV**: Raw data

## Delivery Options

### Email Delivery
- Add recipient emails
- Customize email subject
- Include message
- Attach or embed

### Storage
- Save to document library
- Overwrite or version
- Auto-organize by date

### Integration
- Send to Slack channel
- Upload to cloud storage
- Webhook notification

## Report History

### View History
1. Open scheduled report
2. Go to **History** tab
3. See all past runs:
   - Run date
   - Status (Success/Failed)
   - Download link

### Download Past Reports
Click any historical report to download.

## Best Practices

### Report Design
- Focus on actionable data
- Clear visualizations
- Appropriate level of detail
- Consistent format

### Scheduling
- Consider timezone
- Avoid peak hours
- Allow time for review
- Test before sharing widely

### Recipients
- Right people, right reports
- Minimize information overload
- Secure distribution
- Maintain recipient list

## Email Configuration

Scheduled reports are delivered via email. If email is not configured, reports will still generate but delivery will be simulated.

### Checking Email Status

The Scheduled Reports page shows the current email configuration status:

- **Green indicator**: Email is configured and active
- **Amber indicator**: Email is in demo mode (console logging only)

### Configuring Email

To enable email delivery, configure one of the following:

1. **SMTP**: Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`
2. **SendGrid**: Set `SENDGRID_API_KEY`
3. **Amazon SES**: Set `AWS_SES_REGION` with AWS credentials

See the [Environment Configuration Guide](/docs/ENV_CONFIGURATION.md) for details.

### Demo Mode

When email is not configured:
- Reports still generate on schedule
- Report files are saved to the document library
- Email delivery is logged to the console instead of sent
- The UI displays "Email notifications are in demo mode"

## Troubleshooting

### Report Not Generating
1. Check schedule configuration
2. Verify report is active
3. Check for errors in history
4. Review parameters

### Report Not Delivered
1. Check email configuration status on the page
2. Verify recipient email addresses
3. Check email provider settings
4. Review server logs for delivery errors

### Empty Report
1. Verify date range
2. Check filters
3. Confirm data exists
4. Review access permissions

## Related Topics

- [Report Builder](report-builder.md)
- [Export Options](exports.md)

