package org.logstash.plugins.codecs.lamp;

/**
 * Created by rup on 27/06/2022.
 */

public class Lamp {

    boolean isOn;

    public Lamp() {
        this.isOn = false;
    }

    // method to turn on the light
    void turnOn() {
      this.isOn = true;

    }

    // method to turnoff the light
    void turnOff() {
      this.isOn = false;
    }   

    void toggle() {
      if(this.isOn == true) {
         this.isOn = false;
      }
      else {
         this.isOn = true;
      }
    }

    boolean state() {
       return this.isOn;
    }

}

