import loadCSS from './loadcss';

const global = window;
const define = (window && window.define) || define;
const dependencies = ['module', 'js/qlik', 'general.utils/drag-and-drop-service'];

define(dependencies,
  function(module, qlik, qlikDragDropService){
    const ROOT_URI = module.uri.split('/').slice(0, -1).join('/');
    const DEPENDENCIES_TO_LOAD = {
      React: `${ROOT_URI}/vendors/react.min`
    };
    loadCSS(`${ROOT_URI}/styles.css`);

    let initialProperties = require('./initialProperties');
    let definition = require('./definition');
    let paintMethod = require('./components/main');
    let {lazyLoader, isDependenciesLoaded} = require('./lazyLoad');

    const injectAndCallPaintMethod = function(context, method, ...args) {
          context.paint = method;
          context.paint(...args);
    };
    // load into the global context required libraries using provided "map" object
    const lazyLoad = lazyLoader(global,
      global.require,
      DEPENDENCIES_TO_LOAD,
      injectAndCallPaintMethod);

    let paint = function ($element, layout) {
      let self = this;

      // injecting some services through layout object
      if(layout) {
        if(!layout.services) layout.services = {};
        layout.services.qlik = qlik;
        layout.services.qlikDragDropService = qlikDragDropService;
      }

      if(!isDependenciesLoaded(global, DEPENDENCIES_TO_LOAD))
        lazyLoad(self, paintMethod, $element, layout);
      else
        injectAndCallPaintMethod(self, paintMethod, $element, layout);
    };

    return {
      initialProperties,
      definition,
      paint,
      snapshot: {
        canTakeSnapshot : true
      }
    }
  }
);
