const exporess = require('express');
const router = exporess.Router();
const {
    getAllEmployees,
    createNewEmployee,
    updateEmployee,
    deleteEmployee,
    getEmployee
} = require('../../controllers/employeesController');
const ROLES_LIST = require('../../config/roles_List');
const verifyRoles = require('../../middleware/verifyRoles');

router.route('/')
    .get(getAllEmployees)
    .post(verifyRoles(ROLES_LIST.Admin,ROLES_LIST.Editor),createNewEmployee)
    .put(verifyRoles(ROLES_LIST.Admin,ROLES_LIST.Editor),updateEmployee)
    .delete(verifyRoles(ROLES_LIST.Admin),deleteEmployee);

router.route('/:id')
    .get(getEmployee);


module.exports = router;