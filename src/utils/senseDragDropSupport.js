import React from 'react';
import isEqual from 'lodash.isequal';
import Component from '../components/base';

// used in the DragDropSupport below
function start(drag) {
  // drag.info.type: "libraryitem", "gridcell",...?
  //console.log('dnd start', drag);
  let type = drag.info.type;
  let shouldAccept = this.accept[type] &&
   'function' == typeof this.accept[type] ? this.accept[type].call(this, drag) : this.accept[type];

  //console.log('dnd should accept', shouldAccept);
  if(shouldAccept) {
    // Accept object with the following spec:
    // prio : 1,
    // targetRect : rect,
    // drawRect : rect,
    // cellRect : rect,
    // drop : dropFn(splitCell, sheet)
    drag.registerDropRect(this);
  }
}

function end() {
  //console.log('end drag drop');
}

/**
* @params spec - sense drag and drop specification object:
* accept(info) {}
* start(info) {}
* enter(info) {}
* leave(info) {}
* end(info) {}
* drop(info) {}
* placeClassName - the element class name where sense object should be injected
*/
export default function DragDropSupport(spec = {}) {
  return function AddDragDropSupport(DecorateComponent) {
    const displayName =
     DecorateComponent.displayName ||
     DecorateComponent.name ||
     'Component';

    class DragDropContainer extends Component {
      constructor(props) {
        super(props);
        this.state = {
          isObjectInjected: false,
          itemid: null, // item id
          item: null, // dropped item info
          object: null // injected sense object
        }

        // qlik services. see component.js
        this.qlikDragDropService = props.layout.services.qlikDragDropService;
        this.qlik = props.layout.services.qlik;

        this.DecoratedComponent = DecorateComponent;
        this.displayName = `DragDropContainer > ${displayName}`;

        // accept only objects of specified type
        this.accept = {
          libraryitem: () => { return true },
          gridcell: () => { return true }
        };

        // drop handlers
        this.drop = {
          gridcell: (item) => { console.log(item); this.setState( { item: item, itemid: item.cell.id } ); },
          libraryitem: (item) => { console.log(item); this.setState( { item: item, itemid: item.item.id } ); }
        };

        // priority
        this.prio = 1;
        // start, end ... methods for DnD support
        this.start = start.bind(this);
        this.end = end.bind(this);
      }

      componentDidMount() {
        if(this.qlikDragDropService) {
          this.setupDragDropRect();
          this.qlikDragDropService.registerDropTarget(this);
        }
        this.injectObject();
      }

      componentWillUnmount() {
        this.removeObject();
        console.log('WillUnmount');
        if(this.qlikDragDropService) {
          this.qlikDragDropService.unregisterDropTarget(this);
        }

        this.targetRect = null;
        this.drawRect = null;
        this.cellRect = null;
      }

      componentDidUpdate() {
        this.injectObject();
        this.repaintObject();
      }

      render() {
        const DecoratedComponent = this.DecoratedComponent;
        return <DecoratedComponent {...this.props} item={this.state.item} ref='child'/>;
      }

      // Drag and drop support methods and props
      // "libraryitem", "gridcell",...?
      getRect(){
        let br = React.findDOMNode(this.refs.child).getBoundingClientRect();
        return {
          left: br.left,
          top: br.top,
          right: br.right || (br.left + br.width),
          bottom: br.bottom || (br.top + br.height)
        }
      }

      setupDragDropRect() {
        // see render
        let r = this.getRect();

        this.targetRect = r;
        this.drawRect = r;
        this.cellRect = r;
      }

      getPlaceholderElement() {
        let element = React.findDOMNode(this);
        let placeholder = element.getElementsByClassName(this.placeClassName || "placeholder")[0];
        if(!placeholder) placeholder = element;
        return element;
      }

      injectObject(){
        console.log('injectObject');
        if(!this.state.isObjectInjected && this.state.itemid) {
          let id = this.state.itemid;
          this.removeObject();
          let placeElement = this.getPlaceholderElement();
          console.log(placeElement);
          if(placeElement) {
            this.qlik.currApp().getObject(placeElement, id).then((object) => {
              this.setState({ object: object,  isObjectInjected: true});
              //this.qlik.resize(id);
            });
          }
        }
      }

      repaintObject(){
        let r = this.getRect();
        if(!isEqual(this.cellRect, r)) {
          this.setupDragDropRect();
          if(this.state.object)
            this.qlik.resize(this.state.object);
        }
      }

      removeObject(){
        if(this.state.object) {
          this.state.object.close();
          this.setState({object: null, isObjectInjected: false});
          //let placeElement = this.getPlaceholderElement();
          //if(placeElement) placeElement.innerHTML = '';
        }
      }
    }

    // assign sense dnd support method
    Object.assign(DragDropContainer.prototype, spec);

    return DragDropContainer;
  }
}
