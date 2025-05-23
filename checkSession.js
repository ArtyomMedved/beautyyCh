module.exports = function (monitoredPaths = []) {
    return function (req, res, next) {
      // Проверяем, находится ли текущий путь в списке отслеживаемых
      if (!monitoredPaths.includes(req.path)) {
        return next();
      }
  
      const session = req.cookies?.session;
  
      if (!session) {
        console.log(`[!] No session cookie found. Redirecting from ${req.path} to /`);
        return res.redirect('/');
      }
  
      next();
    };
  };
  