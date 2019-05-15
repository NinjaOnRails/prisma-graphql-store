const { forwardTo } = require('prisma-binding');

const Query = {
  items: forwardTo('db'),
  item: forwardTo('db'),
  itemsConnection: forwardTo('db'),
  // items(parents, args, ctx, info) {
  //   return ctx.db.query.items();
  // },
};

module.exports = Query;
