import React, { useState } from 'react';
import {
  Box,
  Button,
  TextField,
  Typography,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

const EducationalDetails = () => {
  const [expanded, setExpanded] = useState(false);
  const [formData, setFormData] = useState({
    tenth: {
      institutionName: '',
      location: '',
      startDate: '',
      endDate: '',
      syllabusType: ''
    },
    inter: {
      institutionName: '',
      location: '',
      startDate: '',
      endDate: '',
      syllabusType: ''
    },
    ug: {
      institutionName: '',
      location: '',
      startDate: '',
      endDate: '',
      instituteType: ''
    },
    pg: {
      institutionName: '',
      location: '',
      startDate: '',
      endDate: '',
      instituteType: ''
    }
  });

  const handleChange = (panel) => (event, isExpanded) => {
    setExpanded(isExpanded ? panel : false);
  };

  const handleInputChange = (section, field, value) => {
    setFormData(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [field]: value
      }
    }));
  };

  const handlePrevious = () => {
    // Navigate to previous page
    console.log('Navigate to previous page');
  };

  const handleNext = () => {
    // Navigate to next page
    console.log('Form Data:', formData);
  };

  const renderCommonFields = (section) => (
    <>
      <TextField
        fullWidth
        margin="normal"
        label="Institution Name"
        value={formData[section].institutionName}
        onChange={(e) => handleInputChange(section, 'institutionName', e.target.value)}
      />
      <TextField
        fullWidth
        margin="normal"
        label="Location"
        value={formData[section].location}
        onChange={(e) => handleInputChange(section, 'location', e.target.value)}
      />
      <Grid container spacing={2}>
        <Grid item xs={6}>
          <TextField
            fullWidth
            margin="normal"
            label="Start Date"
            type="date"
            InputLabelProps={{ shrink: true }}
            value={formData[section].startDate}
            onChange={(e) => handleInputChange(section, 'startDate', e.target.value)}
          />
        </Grid>
        <Grid item xs={6}>
          <TextField
            fullWidth
            margin="normal"
            label="End Date"
            type="date"
            InputLabelProps={{ shrink: true }}
            value={formData[section].endDate}
            onChange={(e) => handleInputChange(section, 'endDate', e.target.value)}
          />
        </Grid>
      </Grid>
    </>
  );

  return (
    <Box sx={{ maxWidth: 800, margin: 'auto', p: 3 }}>
      <Typography variant="h5" gutterBottom>
        Educational Details
      </Typography>

      <Accordion expanded={expanded === 'tenth'} onChange={handleChange('tenth')}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography>10th Standard Details</Typography>
        </AccordionSummary>
        <AccordionDetails>
          {renderCommonFields('tenth')}
          <FormControl fullWidth margin="normal">
            <InputLabel>Syllabus Type</InputLabel>
            <Select
              value={formData.tenth.syllabusType}
              onChange={(e) => handleInputChange('tenth', 'syllabusType', e.target.value)}
            >
              <MenuItem value="CBSE">CBSE</MenuItem>
              <MenuItem value="SSC">SSC</MenuItem>
            </Select>
          </FormControl>
        </AccordionDetails>
      </Accordion>

      <Accordion expanded={expanded === 'inter'} onChange={handleChange('inter')}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography>Intermediate Details</Typography>
        </AccordionSummary>
        <AccordionDetails>
          {renderCommonFields('inter')}
          <FormControl fullWidth margin="normal">
            <InputLabel>Syllabus Type</InputLabel>
            <Select
              value={formData.inter.syllabusType}
              onChange={(e) => handleInputChange('inter', 'syllabusType', e.target.value)}
            >
              <MenuItem value="CBSE">CBSE</MenuItem>
              <MenuItem value="SSC">SSC</MenuItem>
            </Select>
          </FormControl>
        </AccordionDetails>
      </Accordion>

      <Accordion expanded={expanded === 'ug'} onChange={handleChange('ug')}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography>Under Graduate Details</Typography>
        </AccordionSummary>
        <AccordionDetails>
          {renderCommonFields('ug')}
          <FormControl fullWidth margin="normal">
            <InputLabel>Institute Type</InputLabel>
            <Select
              value={formData.ug.instituteType}
              onChange={(e) => handleInputChange('ug', 'instituteType', e.target.value)}
            >
              <MenuItem value="Government">Government</MenuItem>
              <MenuItem value="Private">Private</MenuItem>
              <MenuItem value="Deemed">Deemed</MenuItem>
            </Select>
          </FormControl>
        </AccordionDetails>
      </Accordion>

      <Accordion expanded={expanded === 'pg'} onChange={handleChange('pg')}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography>Post Graduate Details</Typography>
        </AccordionSummary>
        <AccordionDetails>
          {renderCommonFields('pg')}
          <FormControl fullWidth margin="normal">
            <InputLabel>Institute Type</InputLabel>
            <Select
              value={formData.pg.instituteType}
              onChange={(e) => handleInputChange('pg', 'instituteType', e.target.value)}
            >
              <MenuItem value="Government">Government</MenuItem>
              <MenuItem value="Private">Private</MenuItem>
              <MenuItem value="Deemed">Deemed</MenuItem>
            </Select>
          </FormControl>
        </AccordionDetails>
      </Accordion>

      <Box sx={{ mt: 3, display: 'flex', justifyContent: 'space-between' }}>
        <Button variant="contained" color="secondary" onClick={handlePrevious}>
          Previous
        </Button>
        <Button variant="contained" color="primary" onClick={handleNext}>
          Next
        </Button>
      </Box>
    </Box>
  );
};

export default EducationalDetails;
